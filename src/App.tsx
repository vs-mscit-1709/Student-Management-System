/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate, Link, useNavigate } from 'react-router-dom';
import { 
  Users, 
  UserPlus, 
  LogOut, 
  LayoutDashboard, 
  User, 
  Search, 
  Plus, 
  Trash2, 
  Edit2, 
  X, 
  CheckCircle2,
  GraduationCap,
  Mail,
  Phone,
  Calendar,
  BookOpen,
  BarChart3,
  AlertTriangle,
  ArrowLeft,
  KeyRound,
  Eye,
  ExternalLink,
  ShieldCheck,
  Info
} from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { cn } from './lib/utils';
import { useSearchParams } from 'react-router-dom';

// --- Types ---
interface Student {
  id: number;
  first_name: string;
  last_name: string;
  email: string;
  phone: string;
  enrollment_date: string;
  major: string;
  gpa: number;
}

interface UserData {
  username: string;
  role: 'ADMIN' | 'STUDENT';
  student_id?: number;
}

// --- Auth Context Mock (Simplified for this demo) ---
const useAuth = () => {
  const [user, setUser] = useState<UserData | null>(() => {
    const saved = localStorage.getItem('user');
    return saved ? JSON.parse(saved) : null;
  });
  const [token, setToken] = useState<string | null>(localStorage.getItem('token'));

  const login = (newToken: string, newUser: UserData) => {
    localStorage.setItem('token', newToken);
    localStorage.setItem('user', JSON.stringify(newUser));
    setToken(newToken);
    setUser(newUser);
  };

  const logout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    setToken(null);
    setUser(null);
  };

  return { user, token, login, logout, isAuthenticated: !!token };
};

// --- Components ---

const Input = ({ label, ...props }: any) => (
  <div className="space-y-1.5">
    <label className="text-xs font-semibold uppercase tracking-wider text-zinc-500">{label}</label>
    <input 
      {...props} 
      className="w-full px-4 py-2.5 bg-white border border-zinc-200 rounded-xl focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 transition-all outline-none text-sm"
    />
  </div>
);

const Button = ({ children, variant = 'primary', className, ...props }: any) => {
  const variants = {
    primary: 'bg-indigo-600 text-white hover:bg-indigo-700 shadow-sm',
    secondary: 'bg-white text-zinc-700 border border-zinc-200 hover:bg-zinc-50',
    danger: 'bg-rose-500 text-white hover:bg-rose-600 shadow-sm',
    ghost: 'text-zinc-500 hover:text-zinc-900 hover:bg-zinc-100'
  };
  return (
    <button 
      {...props} 
      className={cn("px-4 py-2 rounded-xl font-medium transition-all active:scale-95 flex items-center justify-center gap-2 text-sm disabled:opacity-50", variants[variant as keyof typeof variants], className)}
    >
      {children}
    </button>
  );
};

// --- Pages ---

const LoginPage = ({ onLogin }: any) => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const navigate = useNavigate();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
      });
      const data = await res.json();
      if (res.ok) {
        onLogin(data.token, data.user);
        navigate('/');
      } else {
        setError(data.error);
      }
    } catch (err) {
      setError('Connection error');
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-zinc-50 p-6">
      <motion.div 
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="w-full max-w-md bg-white p-8 rounded-3xl shadow-xl border border-zinc-100"
      >
        <div className="flex justify-center mb-8">
          <div className="w-16 h-16 bg-indigo-600 rounded-2xl flex items-center justify-center shadow-lg shadow-indigo-200">
            <GraduationCap className="w-10 h-10 text-white" />
          </div>
        </div>
        <h1 className="text-2xl font-bold text-center text-zinc-900 mb-2">Welcome Back</h1>
        <p className="text-zinc-500 text-center text-sm mb-8">Manage your students with ease</p>
        
        <form onSubmit={handleSubmit} className="space-y-4">
          <Input label="Username" value={username} onChange={(e: any) => setUsername(e.target.value)} required />
          <Input label="Password" type="password" value={password} onChange={(e: any) => setPassword(e.target.value)} required />
          <div className="flex justify-end">
            <Link to="/forgot-password" size="sm" className="text-xs text-indigo-600 font-semibold hover:underline">Forgot Password?</Link>
          </div>
          {error && <p className="text-rose-500 text-xs font-medium">{error}</p>}
          <Button type="submit" className="w-full py-3 mt-4">Sign In</Button>
        </form>
        
        <p className="mt-8 text-center text-sm text-zinc-500">
          Don't have an account? <Link to="/register" className="text-indigo-600 font-semibold hover:underline">Register as Student</Link>
        </p>
      </motion.div>
    </div>
  );
};

const RegisterPage = () => {
  const [formData, setFormData] = useState({
    username: '', password: '', first_name: '', last_name: '', email: '', major: ''
  });
  const [error, setError] = useState('');
  const [success, setSuccess] = useState(false);
  const navigate = useNavigate();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    try {
      const res = await fetch('/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(formData)
      });
      const data = await res.json();
      if (res.ok) {
        setSuccess(true);
        setTimeout(() => navigate('/login'), 2000);
      } else {
        setError(data.error);
      }
    } catch (err) {
      setError('Connection error');
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-zinc-50 p-6">
      <motion.div 
        initial={{ opacity: 0, scale: 0.95 }}
        animate={{ opacity: 1, scale: 1 }}
        className="w-full max-w-2xl bg-white p-10 rounded-3xl shadow-xl border border-zinc-100"
      >
        <h1 className="text-2xl font-bold text-zinc-900 mb-6">Student Registration</h1>
        {success ? (
          <div className="text-center py-12">
            <CheckCircle2 className="w-16 h-16 text-emerald-500 mx-auto mb-4" />
            <h2 className="text-xl font-bold text-zinc-900">Registration Successful!</h2>
            <p className="text-zinc-500">Redirecting to login...</p>
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <Input label="Username" value={formData.username} onChange={(e: any) => setFormData({...formData, username: e.target.value})} required />
            <Input label="Password" type="password" value={formData.password} onChange={(e: any) => setFormData({...formData, password: e.target.value})} required />
            <Input label="First Name" value={formData.first_name} onChange={(e: any) => setFormData({...formData, first_name: e.target.value})} required />
            <Input label="Last Name" value={formData.last_name} onChange={(e: any) => setFormData({...formData, last_name: e.target.value})} required />
            <Input label="Email" type="email" value={formData.email} onChange={(e: any) => setFormData({...formData, email: e.target.value})} required />
            <Input label="Major" value={formData.major} onChange={(e: any) => setFormData({...formData, major: e.target.value})} required />
            <div className="md:col-span-2">
              {error && <p className="text-rose-500 text-xs font-medium mb-4">{error}</p>}
              <Button type="submit" className="w-full py-3">Create Account</Button>
              <p className="mt-6 text-center text-sm text-zinc-500">
                Already have an account? <Link to="/login" className="text-indigo-600 font-semibold hover:underline">Sign In</Link>
              </p>
            </div>
          </form>
        )}
      </motion.div>
    </div>
  );
};

const ForgotPasswordPage = () => {
  const [email, setEmail] = useState('');
  const [status, setStatus] = useState<'idle' | 'loading' | 'success' | 'error'>('idle');
  const [message, setMessage] = useState('');
  const [debugLink, setDebugLink] = useState('');
  const navigate = useNavigate();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setStatus('loading');
    try {
      const res = await fetch('/api/auth/forgot-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email })
      });
      const data = await res.json();
      if (res.ok) {
        setStatus('success');
        setMessage(data.message);
        if (data.debug_link) setDebugLink(data.debug_link);
      } else {
        setStatus('error');
        setMessage(data.error);
      }
    } catch (err) {
      setStatus('error');
      setMessage('Connection error');
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-zinc-50 p-6">
      <motion.div 
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="w-full max-w-md bg-white p-8 rounded-3xl shadow-xl border border-zinc-100"
      >
        <Link to="/login" className="inline-flex items-center gap-2 text-sm text-zinc-500 hover:text-indigo-600 mb-6 transition-colors">
          <ArrowLeft className="w-4 h-4" /> Back to Login
        </Link>
        <h1 className="text-2xl font-bold text-zinc-900 mb-2">Forgot Password?</h1>
        <p className="text-zinc-500 text-sm mb-8">Enter your email and we'll send you a link to reset your password.</p>
        
        {status === 'success' ? (
          <div className="space-y-4">
            <div className="bg-emerald-50 p-6 rounded-2xl border border-emerald-100 text-center">
              <CheckCircle2 className="w-12 h-12 text-emerald-500 mx-auto mb-3" />
              <p className="text-emerald-800 font-semibold mb-1">Email Sent!</p>
              <p className="text-emerald-600 text-sm">{message}</p>
            </div>
            {debugLink && (
              <div className="p-4 bg-indigo-50 rounded-2xl border border-indigo-100">
                <div className="flex items-center gap-2 text-indigo-700 font-bold text-xs mb-2">
                  <Info className="w-3 h-3" /> DEMO MODE: RESET LINK
                </div>
                <p className="text-[10px] text-indigo-600 break-all mb-3">{debugLink}</p>
                <a 
                  href={debugLink} 
                  className="block w-full py-2 bg-indigo-600 text-white text-center rounded-xl text-xs font-bold hover:bg-indigo-700 transition-colors"
                >
                  Click here to Reset Now
                </a>
              </div>
            )}
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="space-y-4">
            <Input label="Email Address" type="email" value={email} onChange={(e: any) => setEmail(e.target.value)} required />
            {status === 'error' && <p className="text-rose-500 text-xs font-medium">{message}</p>}
            <Button type="submit" className="w-full py-3 mt-4" disabled={status === 'loading'}>
              {status === 'loading' ? 'Sending...' : 'Send Reset Link'}
            </Button>
          </form>
        )}
      </motion.div>
    </div>
  );
};

const ResetPasswordPage = () => {
  const [searchParams] = useSearchParams();
  const token = searchParams.get('token');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [status, setStatus] = useState<'idle' | 'loading' | 'success' | 'error'>('idle');
  const [message, setMessage] = useState('');
  const navigate = useNavigate();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (password !== confirmPassword) {
      setStatus('error');
      setMessage('Passwords do not match');
      return;
    }
    setStatus('loading');
    try {
      const res = await fetch('/api/auth/reset-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token, password })
      });
      const data = await res.json();
      if (res.ok) {
        setStatus('success');
        setTimeout(() => navigate('/login'), 3000);
      } else {
        setStatus('error');
        setMessage(data.error);
      }
    } catch (err) {
      setStatus('error');
      setMessage('Connection error');
    }
  };

  if (!token) return <Navigate to="/login" />;

  return (
    <div className="min-h-screen flex items-center justify-center bg-zinc-50 p-6">
      <motion.div 
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="w-full max-w-md bg-white p-8 rounded-3xl shadow-xl border border-zinc-100"
      >
        <div className="w-12 h-12 bg-indigo-100 rounded-2xl flex items-center justify-center mb-6">
          <KeyRound className="w-6 h-6 text-indigo-600" />
        </div>
        <h1 className="text-2xl font-bold text-zinc-900 mb-2">Reset Password</h1>
        <p className="text-zinc-500 text-sm mb-8">Choose a strong password for your account.</p>
        
        {status === 'success' ? (
          <div className="bg-emerald-50 p-6 rounded-2xl border border-emerald-100 text-center">
            <CheckCircle2 className="w-12 h-12 text-emerald-500 mx-auto mb-3" />
            <p className="text-emerald-800 font-semibold mb-1">Password Reset Successful!</p>
            <p className="text-emerald-600 text-sm">Redirecting to login...</p>
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="space-y-4">
            <Input label="New Password" type="password" value={password} onChange={(e: any) => setPassword(e.target.value)} required />
            <Input label="Confirm New Password" type="password" value={confirmPassword} onChange={(e: any) => setConfirmPassword(e.target.value)} required />
            {status === 'error' && <p className="text-rose-500 text-xs font-medium">{message}</p>}
            <Button type="submit" className="w-full py-3 mt-4" disabled={status === 'loading'}>
              {status === 'loading' ? 'Updating...' : 'Update Password'}
            </Button>
          </form>
        )}
      </motion.div>
    </div>
  );
};

const Dashboard = ({ user, token, onLogout }: any) => {
  const [students, setStudents] = useState<Student[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [isDeleteModalOpen, setIsDeleteModalOpen] = useState(false);
  const [isViewModalOpen, setIsViewModalOpen] = useState(false);
  const [studentToDelete, setStudentToDelete] = useState<number | null>(null);
  const [selectedStudent, setSelectedStudent] = useState<Student | null>(null);
  const [editingStudent, setEditingStudent] = useState<Student | null>(null);

  const fetchStudents = async () => {
    try {
      const res = await fetch('/api/students', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      const data = await res.json();
      setStudents(data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchStudents();
  }, []);

  const handleDelete = async () => {
    if (!studentToDelete) return;
    try {
      await fetch(`/api/students/${studentToDelete}`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${token}` }
      });
      setIsDeleteModalOpen(false);
      setStudentToDelete(null);
      fetchStudents();
    } catch (err) {
      console.error(err);
    }
  };

  const filteredStudents = students.filter(s => 
    `${s.first_name} ${s.last_name}`.toLowerCase().includes(search.toLowerCase()) ||
    s.email.toLowerCase().includes(search.toLowerCase()) ||
    s.major.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="min-h-screen bg-zinc-50">
      {/* Sidebar / Header */}
      <nav className="bg-white border-b border-zinc-200 px-6 py-4 sticky top-0 z-10">
        <div className="max-w-7xl mx-auto flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-indigo-600 rounded-xl flex items-center justify-center text-white">
              <GraduationCap className="w-6 h-6" />
            </div>
            <div>
              <h1 className="font-bold text-zinc-900 leading-tight">EduStream</h1>
              <p className="text-[10px] uppercase tracking-widest text-zinc-400 font-bold">Management System</p>
            </div>
          </div>
          
          <div className="flex items-center gap-6">
            <div className="hidden md:flex items-center gap-2 px-3 py-1.5 bg-zinc-100 rounded-full">
              <div className="w-6 h-6 bg-white rounded-full flex items-center justify-center">
                <User className="w-3.5 h-3.5 text-zinc-600" />
              </div>
              <span className="text-sm font-semibold text-zinc-700">{user.username}</span>
              <span className="text-[10px] px-2 py-0.5 bg-indigo-100 text-indigo-700 rounded-full font-bold">{user.role}</span>
            </div>
            <Button variant="ghost" onClick={onLogout} className="text-rose-500 hover:bg-rose-50 hover:text-rose-600">
              <LogOut className="w-4 h-4" />
              <span className="hidden sm:inline">Logout</span>
            </Button>
          </div>
        </div>
      </nav>

      <main className="max-w-7xl mx-auto p-6 md:p-10">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-6 mb-10">
          <div>
            <h2 className="text-3xl font-bold text-zinc-900">
              {user.role === 'ADMIN' ? 'Student Directory' : 'My Profile'}
            </h2>
            <p className="text-zinc-500 mt-1">
              {user.role === 'ADMIN' ? `Managing ${students.length} students enrolled in the system` : 'View and manage your academic information'}
            </p>
          </div>
          
          {user.role === 'ADMIN' && (
            <Button onClick={() => { setEditingStudent(null); setIsModalOpen(true); }} className="h-12 px-6">
              <Plus className="w-5 h-5" />
              Add New Student
            </Button>
          )}
        </div>

        {/* Stats Grid */}
        {user.role === 'ADMIN' && (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6 mb-10">
            {[
              { label: 'Total Students', value: students.length, icon: Users, color: 'bg-blue-500' },
              { label: 'Avg. GPA', value: (students.reduce((acc, s) => acc + s.gpa, 0) / (students.length || 1)).toFixed(2), icon: BarChart3, color: 'bg-emerald-500' },
              { label: 'Active Majors', value: new Set(students.map(s => s.major)).size, icon: BookOpen, color: 'bg-amber-500' },
              { label: 'New This Month', value: students.filter(s => new Date(s.enrollment_date).getMonth() === new Date().getMonth()).length, icon: Calendar, color: 'bg-indigo-500' },
            ].map((stat, i) => (
              <motion.div 
                key={i}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: i * 0.1 }}
                className="bg-white p-6 rounded-3xl border border-zinc-100 shadow-sm flex items-center gap-5"
              >
                <div className={cn("w-12 h-12 rounded-2xl flex items-center justify-center text-white shadow-lg", stat.color)}>
                  <stat.icon className="w-6 h-6" />
                </div>
                <div>
                  <p className="text-xs font-bold text-zinc-400 uppercase tracking-wider">{stat.label}</p>
                  <p className="text-2xl font-bold text-zinc-900">{stat.value}</p>
                </div>
              </motion.div>
            ))}
          </div>
        )}

        {/* Search & Filter */}
        {user.role === 'ADMIN' && (
          <div className="bg-white p-4 rounded-2xl border border-zinc-100 shadow-sm mb-6 flex items-center gap-4">
            <Search className="w-5 h-5 text-zinc-400 ml-2" />
            <input 
              type="text" 
              placeholder="Search by name, email, or major..." 
              className="flex-1 bg-transparent border-none outline-none text-sm text-zinc-700"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>
        )}

        {/* Table / List */}
        <div className="bg-white rounded-3xl border border-zinc-100 shadow-xl overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="bg-zinc-50/50 border-b border-zinc-100">
                  <th className="px-6 py-4 text-[10px] font-bold text-zinc-400 uppercase tracking-widest">Student</th>
                  <th className="px-6 py-4 text-[10px] font-bold text-zinc-400 uppercase tracking-widest">Contact</th>
                  <th className="px-6 py-4 text-[10px] font-bold text-zinc-400 uppercase tracking-widest">Academic</th>
                  <th className="px-6 py-4 text-[10px] font-bold text-zinc-400 uppercase tracking-widest">Enrollment</th>
                  {user.role === 'ADMIN' && <th className="px-6 py-4 text-[10px] font-bold text-zinc-400 uppercase tracking-widest text-right">Actions</th>}
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-50">
                <AnimatePresence mode="popLayout">
                  {filteredStudents.map((student) => (
                    <motion.tr 
                      key={student.id}
                      layout
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      exit={{ opacity: 0 }}
                      className="hover:bg-zinc-50/50 transition-colors group"
                    >
                      <td className="px-6 py-5">
                        <div className="flex items-center gap-4">
                          <div className="w-10 h-10 rounded-full bg-indigo-50 flex items-center justify-center text-indigo-600 font-bold text-sm">
                            {student.first_name[0]}{student.last_name[0]}
                          </div>
                          <div>
                            <p className="font-bold text-zinc-900">{student.first_name} {student.last_name}</p>
                            <p className="text-xs text-zinc-400 font-medium">ID: #{student.id.toString().padStart(4, '0')}</p>
                          </div>
                        </div>
                      </td>
                      <td className="px-6 py-5">
                        <div className="space-y-1">
                          <div className="flex items-center gap-2 text-xs text-zinc-600">
                            <Mail className="w-3 h-3" /> {student.email}
                          </div>
                          <div className="flex items-center gap-2 text-xs text-zinc-600">
                            <Phone className="w-3 h-3" /> {student.phone || 'N/A'}
                          </div>
                        </div>
                      </td>
                      <td className="px-6 py-5">
                        <div className="space-y-1">
                          <p className="text-sm font-semibold text-zinc-700">{student.major}</p>
                          <div className="flex items-center gap-2">
                            <div className="h-1.5 w-24 bg-zinc-100 rounded-full overflow-hidden">
                              <div 
                                className={cn("h-full rounded-full", student.gpa >= 3.5 ? 'bg-emerald-500' : student.gpa >= 2.5 ? 'bg-amber-500' : 'bg-rose-500')} 
                                style={{ width: `${(student.gpa / 4) * 100}%` }}
                              />
                            </div>
                            <span className="text-xs font-bold text-zinc-500">{student.gpa.toFixed(2)}</span>
                          </div>
                        </div>
                      </td>
                      <td className="px-6 py-5">
                        <p className="text-sm text-zinc-600 font-medium">{new Date(student.enrollment_date).toLocaleDateString()}</p>
                      </td>
                      <td className="px-6 py-5 text-right">
                        <div className="flex items-center justify-end gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
                          <Button 
                            variant="secondary" 
                            className="p-2 h-9 w-9 border-indigo-100 text-indigo-600 hover:bg-indigo-50" 
                            onClick={() => { setSelectedStudent(student); setIsViewModalOpen(true); }}
                            title="View Profile"
                          >
                            <Eye className="w-4 h-4" />
                          </Button>
                          {user.role === 'ADMIN' && (
                            <>
                              <Button variant="secondary" className="p-2 h-9 w-9" onClick={() => { setEditingStudent(student); setIsModalOpen(true); }}>
                                <Edit2 className="w-4 h-4" />
                              </Button>
                              <Button variant="danger" className="p-2 h-9 w-9" onClick={() => { setStudentToDelete(student.id); setIsDeleteModalOpen(true); }}>
                                <Trash2 className="w-4 h-4" />
                              </Button>
                            </>
                          )}
                        </div>
                      </td>
                    </motion.tr>
                  ))}
                </AnimatePresence>
                {filteredStudents.length === 0 && !loading && (
                  <tr>
                    <td colSpan={5} className="px-6 py-20 text-center">
                      <div className="max-w-xs mx-auto">
                        <Search className="w-12 h-12 text-zinc-200 mx-auto mb-4" />
                        <p className="text-zinc-900 font-bold">No students found</p>
                        <p className="text-zinc-400 text-sm mt-1">Try adjusting your search or add a new student to the directory.</p>
                      </div>
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </main>

      {/* Modal */}
      <AnimatePresence>
        {isModalOpen && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-6">
            <motion.div 
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={() => setIsModalOpen(false)}
              className="absolute inset-0 bg-zinc-900/40 backdrop-blur-sm"
            />
            <motion.div 
              initial={{ opacity: 0, scale: 0.95, y: 20 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.95, y: 20 }}
              className="relative w-full max-w-2xl bg-white rounded-3xl shadow-2xl overflow-hidden"
            >
              <div className="p-8 border-b border-zinc-100 flex items-center justify-between">
                <h3 className="text-xl font-bold text-zinc-900">{editingStudent ? 'Edit Student' : 'Add New Student'}</h3>
                <button onClick={() => setIsModalOpen(false)} className="p-2 hover:bg-zinc-100 rounded-full transition-colors">
                  <X className="w-5 h-5 text-zinc-400" />
                </button>
              </div>
              <form 
                onSubmit={async (e) => {
                  e.preventDefault();
                  const formData = new FormData(e.currentTarget);
                  const data = Object.fromEntries(formData.entries());
                  const url = editingStudent ? `/api/students/${editingStudent.id}` : '/api/students';
                  const method = editingStudent ? 'PUT' : 'POST';
                  
                  try {
                    const res = await fetch(url, {
                      method,
                      headers: { 
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${token}`
                      },
                      body: JSON.stringify(data)
                    });
                    if (res.ok) {
                      setIsModalOpen(false);
                      fetchStudents();
                    }
                  } catch (err) {
                    console.error(err);
                  }
                }}
                className="p-8 grid grid-cols-1 md:grid-cols-2 gap-6"
              >
                <Input label="First Name" name="first_name" defaultValue={editingStudent?.first_name} required />
                <Input label="Last Name" name="last_name" defaultValue={editingStudent?.last_name} required />
                <Input label="Email" name="email" type="email" defaultValue={editingStudent?.email} required />
                <Input label="Phone" name="phone" defaultValue={editingStudent?.phone} />
                <Input label="Major" name="major" defaultValue={editingStudent?.major} required />
                <Input label="GPA" name="gpa" type="number" step="0.01" min="0" max="4" defaultValue={editingStudent?.gpa} required />
                
                <div className="md:col-span-2 flex justify-end gap-3 mt-4">
                  <Button type="button" variant="secondary" onClick={() => setIsModalOpen(false)}>Cancel</Button>
                  <Button type="submit" className="px-8">
                    {editingStudent ? 'Update Student' : 'Save Student'}
                  </Button>
                </div>
              </form>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* View Profile Modal */}
      <AnimatePresence>
        {isViewModalOpen && selectedStudent && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-6">
            <motion.div 
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={() => setIsViewModalOpen(false)}
              className="absolute inset-0 bg-zinc-900/40 backdrop-blur-sm"
            />
            <motion.div 
              initial={{ opacity: 0, scale: 0.95, y: 20 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.95, y: 20 }}
              className="relative w-full max-w-2xl bg-white rounded-3xl shadow-2xl overflow-hidden"
            >
              <div className="bg-indigo-600 p-8 text-white relative">
                <button onClick={() => setIsViewModalOpen(false)} className="absolute top-6 right-6 p-2 hover:bg-white/10 rounded-full transition-colors">
                  <X className="w-5 h-5" />
                </button>
                <div className="flex flex-col md:flex-row items-center gap-6">
                  <div className="w-24 h-24 rounded-2xl bg-white/20 backdrop-blur-md flex items-center justify-center text-3xl font-bold border border-white/30">
                    {selectedStudent.first_name[0]}{selectedStudent.last_name[0]}
                  </div>
                  <div className="text-center md:text-left">
                    <h3 className="text-2xl font-bold">{selectedStudent.first_name} {selectedStudent.last_name}</h3>
                    <p className="text-indigo-100 font-medium opacity-80">{selectedStudent.major} • Class of {new Date(selectedStudent.enrollment_date).getFullYear() + 4}</p>
                    <div className="mt-4 flex flex-wrap justify-center md:justify-start gap-2">
                      <span className="px-3 py-1 bg-white/10 rounded-full text-xs font-bold border border-white/20">GPA: {selectedStudent.gpa.toFixed(2)}</span>
                      <span className="px-3 py-1 bg-white/10 rounded-full text-xs font-bold border border-white/20">ID: #{selectedStudent.id.toString().padStart(4, '0')}</span>
                    </div>
                  </div>
                </div>
              </div>
              
              <div className="p-8 grid grid-cols-1 md:grid-cols-2 gap-8">
                <div className="space-y-6">
                  <div>
                    <h4 className="text-[10px] font-bold text-zinc-400 uppercase tracking-widest mb-3">Contact Information</h4>
                    <div className="space-y-3">
                      <div className="flex items-center gap-3 text-zinc-600">
                        <div className="w-8 h-8 rounded-lg bg-zinc-50 flex items-center justify-center"><Mail className="w-4 h-4" /></div>
                        <span className="text-sm font-medium">{selectedStudent.email}</span>
                      </div>
                      <div className="flex items-center gap-3 text-zinc-600">
                        <div className="w-8 h-8 rounded-lg bg-zinc-50 flex items-center justify-center"><Phone className="w-4 h-4" /></div>
                        <span className="text-sm font-medium">{selectedStudent.phone || 'No phone provided'}</span>
                      </div>
                    </div>
                  </div>
                  
                  <div>
                    <h4 className="text-[10px] font-bold text-zinc-400 uppercase tracking-widest mb-3">Academic Status</h4>
                    <div className="space-y-3">
                      <div className="flex items-center gap-3 text-zinc-600">
                        <div className="w-8 h-8 rounded-lg bg-zinc-50 flex items-center justify-center"><BookOpen className="w-4 h-4" /></div>
                        <span className="text-sm font-medium">{selectedStudent.major}</span>
                      </div>
                      <div className="flex items-center gap-3 text-zinc-600">
                        <div className="w-8 h-8 rounded-lg bg-zinc-50 flex items-center justify-center"><Calendar className="w-4 h-4" /></div>
                        <span className="text-sm font-medium">Enrolled: {new Date(selectedStudent.enrollment_date).toLocaleDateString()}</span>
                      </div>
                    </div>
                  </div>
                </div>

                <div className="bg-zinc-50 rounded-2xl p-6 border border-zinc-100">
                  <h4 className="text-[10px] font-bold text-zinc-400 uppercase tracking-widest mb-4">Performance Overview</h4>
                  <div className="space-y-4">
                    <div className="flex items-end justify-between">
                      <span className="text-sm font-bold text-zinc-700">Current GPA</span>
                      <span className="text-3xl font-black text-indigo-600">{selectedStudent.gpa.toFixed(2)}</span>
                    </div>
                    <div className="h-3 w-full bg-zinc-200 rounded-full overflow-hidden">
                      <motion.div 
                        initial={{ width: 0 }}
                        animate={{ width: `${(selectedStudent.gpa / 4) * 100}%` }}
                        className={cn("h-full rounded-full", selectedStudent.gpa >= 3.5 ? 'bg-emerald-500' : selectedStudent.gpa >= 2.5 ? 'bg-amber-500' : 'bg-rose-500')}
                      />
                    </div>
                    <p className="text-[10px] text-zinc-400 leading-relaxed italic">
                      Academic standing: {selectedStudent.gpa >= 3.5 ? 'Excellent' : selectedStudent.gpa >= 2.5 ? 'Good' : 'Needs Improvement'}. 
                      This student is currently in good standing with the university.
                    </p>
                  </div>
                </div>
              </div>
              
              <div className="p-8 bg-zinc-50/50 border-t border-zinc-100 flex justify-end">
                <Button variant="secondary" onClick={() => setIsViewModalOpen(false)}>Close Profile</Button>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* Delete Confirmation Modal */}
      <AnimatePresence>
        {isDeleteModalOpen && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-6">
            <motion.div 
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={() => setIsDeleteModalOpen(false)}
              className="absolute inset-0 bg-zinc-900/40 backdrop-blur-sm"
            />
            <motion.div 
              initial={{ opacity: 0, scale: 0.95, y: 20 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.95, y: 20 }}
              className="relative w-full max-w-md bg-white rounded-3xl shadow-2xl overflow-hidden p-8 text-center"
            >
              <div className="w-16 h-16 bg-rose-100 rounded-2xl flex items-center justify-center text-rose-600 mx-auto mb-6">
                <AlertTriangle className="w-8 h-8" />
              </div>
              <h3 className="text-xl font-bold text-zinc-900 mb-2">Confirm Deletion</h3>
              <p className="text-zinc-500 mb-8">Are you sure you want to delete this student? This action cannot be undone and will remove all associated records.</p>
              
              <div className="flex flex-col sm:flex-row gap-3">
                <Button variant="secondary" className="flex-1" onClick={() => setIsDeleteModalOpen(false)}>Cancel</Button>
                <Button variant="danger" className="flex-1" onClick={handleDelete}>Delete Student</Button>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </div>
  );
};

// --- App Root ---

export default function App() {
  const { user, token, login, logout, isAuthenticated } = useAuth();

  return (
    <Router>
      <Routes>
        <Route 
          path="/login" 
          element={!isAuthenticated ? <LoginPage onLogin={login} /> : <Navigate to="/" />} 
        />
        <Route 
          path="/register" 
          element={!isAuthenticated ? <RegisterPage /> : <Navigate to="/" />} 
        />
        <Route 
          path="/forgot-password" 
          element={!isAuthenticated ? <ForgotPasswordPage /> : <Navigate to="/" />} 
        />
        <Route 
          path="/reset-password" 
          element={!isAuthenticated ? <ResetPasswordPage /> : <Navigate to="/" />} 
        />
        <Route 
          path="/" 
          element={isAuthenticated ? <Dashboard user={user} token={token} onLogout={logout} /> : <Navigate to="/login" />} 
        />
        <Route path="*" element={<Navigate to="/" />} />
      </Routes>
    </Router>
  );
}
