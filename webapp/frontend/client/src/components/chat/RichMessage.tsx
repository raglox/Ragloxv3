import React from 'react';

// STABILITY MODE: Using plain text rendering to ensure system stability.
// This isolates the crash from any potential Markdown library issues.

interface RichMessageProps {
    content: string;
    role: 'user' | 'assistant' | 'system';
}

const RichMessage: React.FC<RichMessageProps> = ({ content, role }) => {
    return (
        <div className={`whitespace-pre-wrap ${role === 'user' ? 'text-white' : 'text-gray-300'}`}>
            {content}
        </div>
    );
};

export default RichMessage;
