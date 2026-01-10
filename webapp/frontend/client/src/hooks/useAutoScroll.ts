import { useEffect, useRef, useState } from 'react';

export const useAutoScroll = (dependencies: any[]) => {
    const containerRef = useRef<HTMLDivElement>(null);
    const [showScrollButton, setShowScrollButton] = useState(false);
    const [isAutoScrolling, setIsAutoScrolling] = useState(true);

    const scrollToBottom = () => {
        if (containerRef.current) {
            containerRef.current.scrollTop = containerRef.current.scrollHeight;
        }
    };

    const handleScroll = () => {
        if (!containerRef.current) return;
        
        const { scrollTop, scrollHeight, clientHeight } = containerRef.current;
        const isNearBottom = scrollHeight - scrollTop - clientHeight < 100;
        
        setIsAutoScrolling(isNearBottom);
        setShowScrollButton(!isNearBottom);
    };

    useEffect(() => {
        if (isAutoScrolling) {
            scrollToBottom();
        }
    }, dependencies);

    return { containerRef, showScrollButton, scrollToBottom, handleScroll };
};
