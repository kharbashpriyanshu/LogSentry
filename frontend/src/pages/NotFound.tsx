import { Link } from 'react-router-dom';
import { ShieldAlert, ArrowLeft } from 'lucide-react';

export default function NotFound() {
  return (
    <div className="flex flex-col items-center justify-center h-[70vh] text-center px-4">
      <div className="p-4 bg-red-500/10 border border-red-500/20 rounded-full text-red-500 mb-6 animate-pulse">
        <ShieldAlert className="w-16 h-16" />
      </div>
      <h1 className="text-6xl font-extrabold text-slate-100 tracking-tight">404</h1>
      <h2 className="text-2xl font-bold text-slate-300 mt-2">Access Denied / Route Not Found</h2>
      <p className="text-slate-500 text-sm mt-3 max-w-sm">
        The system path you requested is restricted or does not exist. Ensure the URL endpoint is correct.
      </p>
      <Link
        to="/dashboard"
        className="mt-8 bg-primary hover:bg-primary-hover text-white font-medium py-2.5 px-6 rounded-lg transition-colors flex items-center gap-2 text-sm cursor-pointer"
      >
        <ArrowLeft className="w-4 h-4" /> Return to Command Center
      </Link>
    </div>
  );
}
