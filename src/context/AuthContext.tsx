import React, { createContext, useContext, useState, useEffect } from 'react';
import { User } from 'firebase/auth';
import { AuthService } from '../firebase/authService';
import { UserProfile, UserRole } from '../types';

interface AuthContextType {
  user: User | null;
  userProfile: UserProfile | null;
  role: UserRole;
  isAdmin: boolean;
  isAnalyst: boolean;
  loading: boolean;
  login: (email: string, pass: string, role?: UserRole) => Promise<void>;
  register: (email: string, pass: string, role?: UserRole) => Promise<void>;
  quickDemoLogin: (role: UserRole) => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | null>(null);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [userProfile, setUserProfile] = useState<UserProfile | null>(AuthService.getCachedProfile());
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const unsub = AuthService.subscribeToAuth((fbUser, profile) => {
      setUser(fbUser);
      setUserProfile(profile);
      setLoading(false);
    });

    return () => unsub();
  }, []);

  const login = async (email: string, pass: string, role?: UserRole) => {
    setLoading(true);
    try {
      const profile = await AuthService.login(email, pass, role);
      setUserProfile(profile);
    } finally {
      setLoading(false);
    }
  };

  const register = async (email: string, pass: string, role: UserRole = 'analyst') => {
    setLoading(true);
    try {
      const profile = await AuthService.register(email, pass, role);
      setUserProfile(profile);
    } finally {
      setLoading(false);
    }
  };

  const quickDemoLogin = async (targetRole: UserRole) => {
    setLoading(true);
    try {
      const email = targetRole === 'admin' ? 'admin@security.local' : 'analyst@security.local';
      const pass = 'demo123456';
      const profile = await AuthService.login(email, pass, targetRole);
      setUserProfile(profile);
    } finally {
      setLoading(false);
    }
  };

  const logout = async () => {
    setLoading(true);
    try {
      await AuthService.logout(userProfile?.email);
      setUser(null);
      setUserProfile(null);
    } finally {
      setLoading(false);
    }
  };

  const role: UserRole = userProfile?.role || 'analyst';
  const isAdmin = role === 'admin';
  const isAnalyst = role === 'analyst';

  return (
    <AuthContext.Provider
      value={{
        user,
        userProfile,
        role,
        isAdmin,
        isAnalyst,
        loading,
        login,
        register,
        quickDemoLogin,
        logout
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export function useAuth(): AuthContextType {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return ctx;
}
