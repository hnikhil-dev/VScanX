import { knowledgeBase } from "./knowledgeBase";

const STOP_WORDS = new Set([
  "the", "a", "an", "and", "or", "but", "is", "are", "was", "were", 
  "be", "been", "being", "to", "for", "of", "in", "on", "at", "by",
  "with", "about", "against", "between", "into", "through", "during",
  "before", "after", "above", "below", "from", "up", "down", "out",
  "over", "under", "again", "further", "then", "once", "here", "there",
  "when", "where", "why", "how", "all", "any", "both", "each", "few",
  "more", "most", "other", "some", "such", "no", "nor", "not", "only",
  "own", "same", "so", "than", "too", "very", "can", "will", "just",
  "should", "now", "this", "that", "these", "those"
]);

// Helper to tokenize and clean text
function tokenize(text) {
  if (!text) return [];
  return text
    .toLowerCase()
    .replace(/[^\w\s-]/g, "") // remove punctuation except hyphens
    .split(/\s+/)
    .filter(token => token.length > 2 && !STOP_WORDS.has(token));
}

// Smart detector to extract active page category when standard queries yield weak direct matches
function detectActiveCategory(selectedText, customQuery, pageContent) {
  const combined = `${selectedText || ""} ${customQuery || ""} ${pageContent || ""}`.toLowerCase();
  
  if (combined.includes("plugin") || combined.includes("orchestrator") || combined.includes("concurrency") || combined.includes("thread")) {
    return "internals";
  }
  if (combined.includes("replay") || combined.includes("diff") || combined.includes("snap_") || combined.includes("comparison")) {
    return "replay-diff";
  }
  if (combined.includes("finding") || combined.includes("schema") || combined.includes("vsc-")) {
    return "findings";
  }
  if (combined.includes("reentrancy") || combined.includes("solidity") || combined.includes("web3") || combined.includes("ssrf") || combined.includes("sqli")) {
    return "modules";
  }
  if (combined.includes("installation") || combined.includes("prerequisites") || combined.includes("setup") || combined.includes("install")) {
    return "getting-started";
  }
  if (combined.includes("sandbox") || combined.includes("lifecycle") || combined.includes("stage")) {
    return "workflow";
  }
  return null;
}

export function retrieveDocumentation(selectedText, customQuery = "", pageContent = "") {
  const contextTokens = tokenize(selectedText);
  const queryTokens = tokenize(customQuery);
  const pageTokens = tokenize(pageContent);
  
  // Apply structured RAG weights
  const tokenWeights = {};
  
  // 1. Custom query tokens (Highest priority user intent) - Multiplier: 2.0
  queryTokens.forEach(token => {
    tokenWeights[token] = Math.max(tokenWeights[token] || 0, 2.0);
  });
  
  // 2. Selected highlight tokens (Focus area) - Multiplier: 1.5
  contextTokens.forEach(token => {
    tokenWeights[token] = Math.max(tokenWeights[token] || 0, 1.5);
  });
  
  // 3. Background page content tokens (Implicit context) - Multiplier: 0.5
  pageTokens.forEach(token => {
    tokenWeights[token] = Math.max(tokenWeights[token] || 0, 0.5);
  });
  
  const uniqueTokens = Object.keys(tokenWeights);
  const lowercaseText = `${selectedText || ""} ${customQuery || ""} ${pageContent || ""}`.trim().toLowerCase();
  
  // Dynamic keyword-overlap promotions to boost exact structural references
  const promotedIds = [];
  if (lowercaseText.includes("pluginmanage") || lowercaseText.includes("pluginmanager") || lowercaseText.includes("plugin_manager")) {
    promotedIds.push("system-internals-plugin");
  }
  if (lowercaseText.includes("mental model") || lowercaseText.includes("mental_model") || (lowercaseText.includes("mental") && lowercaseText.includes("model"))) {
    promotedIds.push("core-concepts-principles");
    promotedIds.push("core-concepts-evolving-states");
  }
  if (lowercaseText.includes("scan_701d") || lowercaseText.includes("701d")) {
    promotedIds.push("scanner-modules-web3");
    promotedIds.push("replay-diff-serialization");
  }
  if (lowercaseText.includes("vscanx scan")) {
    promotedIds.push("getting-started-usage");
    promotedIds.push("verification-workflow-lifecycle");
  }
  if (lowercaseText.includes("reentrancy")) {
    promotedIds.push("scanner-modules-web3");
    promotedIds.push("verification-workflow-sandboxes");
  }

  // Score all database chunks
  const scoredChunks = knowledgeBase.map(chunk => {
    let score = 0;
    
    // Check if promoted
    if (promotedIds.includes(chunk.id)) {
      score += 60; // Dynamic promotion weight boost
    }
    
    // Tokenize chunk fields
    const titleTokens = tokenize(chunk.title);
    const contentTokens = tokenize(chunk.content);
    const tagTokens = chunk.tags.map(t => t.toLowerCase());

    uniqueTokens.forEach(token => {
      const weight = tokenWeights[token];
      let tokenScore = 0;
      
      // Check if this token belongs to the explicit user intent (highlighted text or custom query)
      const isUserIntent = contextTokens.includes(token) || queryTokens.includes(token);
      
      if (isUserIntent) {
        // A. Tag match (Highest priority for explicit selection/query)
        if (tagTokens.includes(token)) {
          tokenScore += 10;
        }
        
        // B. Title match (High priority for explicit selection/query)
        if (titleTokens.includes(token)) {
          tokenScore += 6;
        }
      } else {
        // Background page content: tags serve as low-impact signals only
        if (tagTokens.includes(token)) {
          tokenScore += 1.5;
        }
      }
      
      // C. Category match
      if (chunk.category.toLowerCase() === token) {
        tokenScore += 3;
      }

      // D. Content match (Normal priority)
      if (contentTokens.includes(token)) {
        tokenScore += 1.5;
      }
      
      // E. Raw substring match helper for exact CLI flags or IDs
      if (chunk.content.toLowerCase().includes(token)) {
        tokenScore += 0.5;
      }
      
      score += tokenScore * weight;
    });

    return { chunk, score };
  });

  // Sort by score descending and filter chunks with a minimum match threshold
  let sorted = scoredChunks
    .filter(item => item.score > 2.0)
    .sort((a, b) => b.score - a.score);

  let matchTier = "Limited Documentation Context";
  let explanation = "No matching documentation anchors were identified for the selected text.";

  // If standard scoring fails to find strong matches, trigger the category fallback
  if (sorted.length === 0) {
    const activeCategory = detectActiveCategory(selectedText, customQuery, pageContent);
    if (activeCategory) {
      const fallbackChunks = knowledgeBase.filter(c => c.category === activeCategory);
      if (fallbackChunks.length > 0) {
        sorted = fallbackChunks.slice(0, 2).map(c => ({ chunk: c, score: 3.5 }));
        matchTier = "Contextual Match Available";
        explanation = `Anchored to ${activeCategory.replace("-", " ")} documentation based on the active page context.`;
      }
    }
  } else {
    // Determine honest, discrete match tiers
    const topScore = sorted[0].score;
    if (topScore >= 50) {
      matchTier = "Strong Retrieval Match";
      explanation = `Highly relevant technical anchors mapped directly to ${sorted.length} documentation source(s).`;
    } else if (topScore >= 15) {
      matchTier = "Medium Retrieval Match";
      explanation = `Grounded via specific keywords matched across ${sorted.length} documentation section(s).`;
    } else {
      matchTier = "Weak Retrieval Match";
      explanation = `Partial keyword overlapping detected in ${sorted.length} reference chunk(s).`;
    }
  }

  const finalSources = sorted.slice(0, 3).map(item => item.chunk);

  return {
    sources: finalSources,
    matchTier,
    explanation
  };
}
