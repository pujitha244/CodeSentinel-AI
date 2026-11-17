import React, { useState } from 'react';
import { Project, Audit, AssistantMessage } from '../types';
import { api } from '../services/api';
import { Bot, User, Send, Sparkles, Loader2, FileCode, Shield } from 'lucide-react';

interface AssistantPageProps {
  currentProject: Project | null;
  latestAudit: Audit | null;
}

export const AssistantPage: React.FC<AssistantPageProps> = ({ currentProject, latestAudit }) => {
  const [messages, setMessages] = useState<AssistantMessage[]>([
    {
      role: 'assistant',
      content: "Hello! I am your CodeSentinel Security & Architecture Intelligence Assistant. I am grounded directly in your repository's static AST relationships, discovered vulnerability chains, and security findings. How can I assist you with your audit today?"
    }
  ]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);

  const quickPrompts = [
    "Explain the SQL injection vulnerability chain",
    "What should I fix first based on risk priority?",
    "Explain this repository's architectural structure",
    "Which logic gaps or edge cases need defensive validation?"
  ];

  const handleSend = async (queryText?: string) => {
    const textToSend = queryText || input;
    if (!textToSend.trim() || !currentProject) return;

    const userMsg: AssistantMessage = { role: 'user', content: textToSend };
    const updatedMessages = [...messages, userMsg];
    setMessages(updatedMessages);
    setInput('');
    setLoading(true);

    try {
      const response = await api.chatWithAssistant(
        currentProject.id,
        latestAudit ? latestAudit.id : null,
        updatedMessages
      );

      setMessages([
        ...updatedMessages,
        {
          role: 'assistant',
          content: response.reply,
          evidence_references: response.evidence_references
        }
      ]);
      setLoading(false);
    } catch (err: any) {
      setMessages([
        ...updatedMessages,
        {
          role: 'assistant',
          content: "Sorry, I encountered an error communicating with the intelligence service."
        }
      ]);
      setLoading(false);
    }
  };

  if (!currentProject) {
    return (
      <div className="py-20 text-center text-xs text-slate-500">
        Please load or ingest a project to enable the AI Security Assistant.
      </div>
    );
  }

  return (
    <div className="flex flex-col h-[calc(100vh-6rem)] max-w-5xl mx-auto py-4 px-6">
      {/* Header */}
      <div className="pb-4 border-b border-slate-800 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-xl bg-cyan-950 border border-cyan-800 text-cyan-400">
            <Bot className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-lg font-bold text-white">Repository-Aware AI Assistant</h1>
            <p className="text-xs text-slate-400">
              Grounded strictly in verified repository evidence • Rule-based & LLM provider agnostic
            </p>
          </div>
        </div>

        <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
          Project: {currentProject.name}
        </span>
      </div>

      {/* Messages Scroll Area */}
      <div className="flex-1 overflow-y-auto py-4 space-y-4 pr-2">
        {messages.map((m, idx) => (
          <div
            key={idx}
            className={`flex items-start gap-3 ${
              m.role === 'user' ? 'justify-end' : 'justify-start'
            }`}
          >
            {m.role === 'assistant' && (
              <div className="w-8 h-8 rounded-lg bg-cyan-950 border border-cyan-800 flex items-center justify-center shrink-0 text-cyan-400">
                <Bot className="w-4 h-4" />
              </div>
            )}

            <div
              className={`max-w-2xl rounded-2xl p-4 text-xs leading-relaxed ${
                m.role === 'user'
                  ? 'bg-cyan-600 text-white rounded-br-none shadow-md shadow-cyan-600/20'
                  : 'bg-sentinel-900 border border-slate-800 text-slate-200 rounded-bl-none shadow-md'
              }`}
            >
              <div className="whitespace-pre-wrap">{m.content}</div>

              {m.evidence_references && m.evidence_references.length > 0 && (
                <div className="mt-3 pt-3 border-t border-slate-800/80 space-y-1">
                  <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-cyan-400">
                    Linked Repository Evidence:
                  </span>
                  {m.evidence_references.map((ev, i) => (
                    <div key={i} className="text-[11px] font-mono text-slate-400 flex items-center gap-1.5">
                      <FileCode className="w-3.5 h-3.5 text-slate-500" />
                      <span>{ev.file}:{ev.line} — {ev.title}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {m.role === 'user' && (
              <div className="w-8 h-8 rounded-lg bg-slate-800 border border-slate-700 flex items-center justify-center shrink-0 text-slate-300">
                <User className="w-4 h-4" />
              </div>
            )}
          </div>
        ))}

        {loading && (
          <div className="flex items-center gap-2 text-xs text-slate-400 font-mono py-2">
            <Loader2 className="w-4 h-4 text-cyan-400 animate-spin" />
            <span>Analyzing repository evidence...</span>
          </div>
        )}
      </div>

      {/* Quick Prompts Chips */}
      <div className="py-2 flex flex-wrap gap-2">
        {quickPrompts.map((prompt, i) => (
          <button
            key={i}
            onClick={() => handleSend(prompt)}
            disabled={loading}
            className="text-[11px] px-3 py-1.5 rounded-lg border border-slate-800 bg-slate-900/60 hover:bg-slate-800 text-slate-300 transition text-left"
          >
            {prompt}
          </button>
        ))}
      </div>

      {/* Input Form */}
      <form
        onSubmit={(e) => {
          e.preventDefault();
          handleSend();
        }}
        className="pt-2 flex items-center gap-2"
      >
        <input
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="Ask CodeSentinel about vulnerabilities, architecture, or edge cases..."
          className="flex-1 px-4 py-2.5 rounded-xl bg-slate-900 border border-slate-800 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
        />
        <button
          type="submit"
          disabled={loading || !input.trim()}
          className="p-2.5 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white transition disabled:opacity-50"
        >
          <Send className="w-4 h-4" />
        </button>
      </form>
    </div>
  );
};
