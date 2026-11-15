import { useState } from "react";
import { Check, Copy } from "lucide-react";

interface CopyButtonProps {
  value: string;
  label: string;
  copiedLabel: string;
  className?: string;
}

// 通用一键复制按钮（复制成功后短暂切换为已复制提示）
export function CopyButton({ value, label, copiedLabel, className = "" }: CopyButtonProps) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 1600);
    } catch {
      // 忽略浏览器剪贴板权限限制
    }
  };

  return (
    <button
      type="button"
      onClick={handleCopy}
      className={`inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md border transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
        copied
          ? "bg-emerald-50 border-emerald-200 text-emerald-700"
          : "bg-white border-slate-200 text-slate-700 hover:bg-slate-50 hover:text-slate-900"
      } ${className}`}
    >
      {copied ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
      <span>{copied ? copiedLabel : label}</span>
    </button>
  );
}
