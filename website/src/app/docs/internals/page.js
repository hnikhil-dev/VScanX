import CodeBlock from "@/components/CodeBlock";

export default function InternalsDocs() {
  return (
    <article className="prose prose-invert prose-zinc max-w-none prose-base sm:prose-lg leading-relaxed select-text">
      
      {/* 1. Quick Summary */}
      <header className="mb-10 select-text">
        <h1 id="overview" className="text-3xl font-extrabold tracking-tight text-zinc-50 mb-3 select-text">
          System Internals & Contributors Guide
        </h1>
        <p className="text-zinc-400 text-lg select-text max-w-3xl">
          Deep-dive into VScanX's underlying runtime orchestration, plugin discovery engine, thread pooling pipelines, and framework standards.
        </p>
      </header>

      {/* 2. Core Mental Model */}
      <section className="space-y-6 select-text mb-12">
        <h2 id="mental-model" className="text-xl font-bold text-zinc-100 border-b border-zinc-900 pb-2 select-text">
          Mental Model
        </h2>
        <p className="text-base text-zinc-400 leading-relaxed select-text">
          This internals guide is prepared exclusively for framework maintainers, core contributors, and advanced users. To keep onboarding simple and frictionless, **new users do not need to understand these internal mechanics to operate VScanX successfully.**
        </p>
        <p className="text-base text-zinc-400 leading-relaxed select-text">
          VScanX organizes its core engine into decoupled Python blocks under <code>core/</code>:
        </p>
        <ul className="list-disc pl-6 text-zinc-400 text-base space-y-2 select-text">
          <li><strong>PluginManager (`core/plugins/manager.py`):</strong> Dynamically mounts and instantiates scanning subclasses at runtime.</li>
          <li><strong>Orchestrator (`core/orchestrator.py`):</strong> Manages thread-pool execution queues, task maps, and validation retries.</li>
          <li><strong>EventBus (`core/events/bus.py`):</strong> Coordinates event propagation across decoupled publishers.</li>
        </ul>
      </section>

      {/* 3. Plugin Loading Mechanics */}
      <section className="space-y-6 select-text mb-12">
        <h2 id="plugin-discovery" className="text-xl font-bold text-zinc-100 border-b border-zinc-900 pb-2 select-text">
          Plugin Discovery & Loading
        </h2>
        <p className="text-base text-zinc-400 leading-relaxed select-text">
          VScanX mounts modules dynamically without hardcoded config imports. When <code>vscanx.py</code> starts, the <code>PluginManager</code> scans the module folders, inspects Python modules for subclasses inheriting <code>BaseModule</code> (from <code>modules.base_module</code>), and registers their signatures:
        </p>

        <CodeBlock code="# core/plugins/manager.py
import importlib
import pkgutil
import inspect
from modules.base_module import BaseModule

class PluginManager:
    def discover_modules(self, directory: str):
        # Walk directory, import modules, and register BaseModule subclasses
        for finder, name, ispkg in pkgutil.walk_packages([directory]):
            mod = importlib.import_module(f'modules.{name}')
            for _, obj in inspect.getmembers(mod, inspect.isclass):
                if issubclass(obj, BaseModule) and obj is not BaseModule:
                    self.register_plugin(obj())" />
      </section>

      {/* 4. Concurrency & Threading Model */}
      <section className="space-y-6 select-text mb-12">
        <h2 id="concurrency" className="text-xl font-bold text-zinc-100 border-b border-zinc-900 pb-2 select-text">
          Orchestration Concurrency
        </h2>
        <p className="text-base text-zinc-400 leading-relaxed select-text">
          The core orchestrator (<code>core/orchestrator.py</code>) utilizes a high-performance thread-pool architecture (<code>concurrent.futures.ThreadPoolExecutor</code>) to handle concurrent module probing.
        </p>
        <p className="text-base text-zinc-400 leading-relaxed select-text">
          To protect host network bandwidth and prevent target socket exhaustion, VScanX enforces strict resource boundaries:
        </p>
        <ul className="list-disc pl-6 text-zinc-400 text-base space-y-2 select-text">
          <li><strong>Thread Limits:</strong> Concurrent tasks are capped at a maximum parameter size (defaulting to 10 threads per scan profile).</li>
          <li><strong>Verification Queues:</strong> Sandbox validators run sequentially or in isolated pools, ensuring dynamic exploit payload traces are executed with high precision.</li>
        </ul>
      </section>

      {/* 5. Contributor Standards Section (New Requirement) */}
      <section className="space-y-6 select-text mb-8">
        <h2 id="contributor-standards" className="text-xl font-bold text-zinc-100 border-b border-zinc-900 pb-2 select-text">
          Framework Contributor Standards
        </h2>
        <p className="text-base text-zinc-400 leading-relaxed select-text">
          To maintain architectural alignment, clean schemas, and clean code styles as VScanX scales, all contributors must adhere strictly to the following standards:
        </p>
        
        <div className="space-y-4 select-text">
          <div className="border border-zinc-900 rounded-lg p-5">
            <h4 className="text-sm font-bold text-zinc-200 mb-2">1. Module Design Standards</h4>
            <p className="text-xs sm:text-sm text-zinc-500 leading-relaxed">
              Every scanning module must inherit <code>BaseModule</code> and override <code>inspect_target()</code>. Passive probes should strictly write zero active payloads to targets, delegating validations fully to sandbox verification engines.
            </p>
          </div>

          <div className="border border-zinc-900 rounded-lg p-5">
            <h4 className="text-sm font-bold text-zinc-200 mb-2">2. Event Schema Standards</h4>
            <p className="text-xs sm:text-sm text-zinc-500 leading-relaxed">
              Custom anomaly events must be defined inside <code>core/events/schemas.py</code>. The schema payload contract must strictly store serialize-friendly parameters (strings, ints, floats) to allow clean disk snapshots.
            </p>
          </div>

          <div className="border border-zinc-900 rounded-lg p-5">
            <h4 className="text-sm font-bold text-zinc-200 mb-2">3. Telemetry & Log Standards</h4>
            <p className="text-xs sm:text-sm text-zinc-500 leading-relaxed">
              Never inject raw <code>print()</code> statements inside framework cores. Always use the structured logger <code>core.logging_config</code>, passing trace IDs and log level parameters (such as <code>logger.debug()</code> or <code>logger.error()</code>) to ensure clean diagnostics outputs.
            </p>
          </div>
        </div>
      </section>

    </article>
  );
}
