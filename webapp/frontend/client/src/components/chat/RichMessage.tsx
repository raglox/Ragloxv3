import React from 'react';
import ReactMarkdown from 'react-markdown';
import rehypeHighlight from 'rehype-highlight';
import remarkGfm from 'remark-gfm';
import 'highlight.js/styles/github-dark.css'; // Or another style

interface RichMessageProps {
    content: string;
    role: 'user' | 'assistant' | 'system';
}

const RichMessage: React.FC<RichMessageProps> = ({ content, role }) => {
    return (
        <div className={`prose prose-invert max-w-none ${role === 'user' ? 'prose-p:text-white' : 'prose-p:text-gray-300'}`}>
            <ReactMarkdown
                remarkPlugins={[remarkGfm]}
                rehypePlugins={[rehypeHighlight]}
                components={{
                    code({ node, inline, className, children, ...props }: any) {
                        const match = /language-(\w+)/.exec(className || '');
                        return !inline && match ? (
                            <div className="relative group">
                                <div className="absolute right-2 top-2 opacity-0 group-hover:opacity-100 transition-opacity">
                                    <button 
                                        onClick={() => navigator.clipboard.writeText(String(children))}
                                        className="text-xs bg-gray-700 hover:bg-gray-600 text-white px-2 py-1 rounded"
                                    >
                                        Copy
                                    </button>
                                </div>
                                <code className={className} {...props}>
                                    {children}
                                </code>
                            </div>
                        ) : (
                            <code className="bg-gray-800 rounded px-1 py-0.5 text-sm" {...props}>
                                {children}
                            </code>
                        );
                    }
                }}
            >
                {content}
            </ReactMarkdown>
        </div>
    );
};

export default RichMessage;
