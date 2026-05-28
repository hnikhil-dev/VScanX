"use client";

import { useState } from "react";
import SelectionBubble from "./SelectionBubble";
import AssistantDrawer from "./AssistantDrawer";

export default function AssistantWrapper({ children }) {
  const [selectedText, setSelectedText] = useState("");
  const [initialQuery, setInitialQuery] = useState("");
  const [pageContent, setPageContent] = useState("");
  const [isDrawerOpen, setIsDrawerOpen] = useState(false);

  const handleTriggerAssistant = (text, query) => {
    setSelectedText(text);
    setInitialQuery(query);
    
    // Dynamic page context extraction
    const docElement = document.querySelector("article") || document.querySelector("main");
    const content = docElement ? docElement.innerText.slice(0, 10000) : "";
    setPageContent(content);
    
    setIsDrawerOpen(true);
  };

  return (
    <>
      {children}
      
      {/* Global Selection Highlight overlay bubble bubble */}
      <SelectionBubble onTriggerAssistant={handleTriggerAssistant} />
      
      {/* Global Slide out workspace panel drawer */}
      <AssistantDrawer 
        isOpen={isDrawerOpen} 
        onClose={() => setIsDrawerOpen(false)} 
        selectedText={selectedText}
        initialQuery={initialQuery}
        pageContent={pageContent}
      />
    </>
  );
}
