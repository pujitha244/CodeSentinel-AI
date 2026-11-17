import React from 'react';
import Editor from '@monaco-editor/react';

interface MonacoCodeViewerProps {
  code: string;
  language?: string;
  highlightLine?: number;
  height?: string;
  readOnly?: boolean;
}

export const MonacoCodeViewer: React.FC<MonacoCodeViewerProps> = ({
  code,
  language = 'python',
  highlightLine,
  height = '420px',
  readOnly = true
}) => {
  const handleEditorDidMount = (editor: any) => {
    if (highlightLine) {
      editor.revealLineInCenter(highlightLine);
      editor.setPosition({ lineNumber: highlightLine, column: 1 });
      editor.deltaDecorations([], [
        {
          range: {
            startLineNumber: highlightLine,
            startColumn: 1,
            endLineNumber: highlightLine,
            endColumn: 100
          },
          options: {
            isWholeLine: true,
            className: 'bg-rose-950/60 border-l-4 border-rose-500',
            glyphMarginClassName: 'bg-rose-500'
          }
        }
      ]);
    }
  };

  return (
    <div className="relative rounded-lg overflow-hidden border border-slate-800 bg-[#1e1e1e] shadow-inner">
      <Editor
        height={height}
        language={language}
        theme="vs-dark"
        value={code}
        onMount={handleEditorDidMount}
        options={{
          readOnly,
          minimap: { enabled: false },
          fontSize: 13,
          lineNumbers: 'on',
          scrollBeyondLastLine: false,
          fontFamily: "'JetBrains Mono', monospace",
          renderLineHighlight: 'all',
          automaticLayout: true
        }}
        loading={
          <div className="flex items-center justify-center h-48 text-sm text-slate-500 font-mono">
            Loading Code View...
          </div>
        }
      />
    </div>
  );
};
