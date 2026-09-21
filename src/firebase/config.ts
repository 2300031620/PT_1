import { initializeApp, getApps, getApp } from 'firebase/app';
import { getFirestore } from 'firebase/firestore';
import { getAuth } from 'firebase/auth';
import appletConfig from '../../firebase-applet-config.json';

// Firebase configuration loaded dynamically using environment variables
// Does not put private Firebase credentials directly into source code
export const firebaseConfig = {
  apiKey: import.meta.env.VITE_FIREBASE_API_KEY || (appletConfig as Record<string, string>).apiKey || '',
  authDomain: import.meta.env.VITE_FIREBASE_AUTH_DOMAIN || (appletConfig as Record<string, string>).authDomain || '',
  projectId: import.meta.env.VITE_FIREBASE_PROJECT_ID || (appletConfig as Record<string, string>).projectId || '',
  firestoreDatabaseId: import.meta.env.VITE_FIREBASE_FIRESTORE_DATABASE_ID || (appletConfig as Record<string, string>).firestoreDatabaseId || '(default)',
  storageBucket: import.meta.env.VITE_FIREBASE_STORAGE_BUCKET || (appletConfig as Record<string, string>).storageBucket || '',
  messagingSenderId: import.meta.env.VITE_FIREBASE_MESSAGING_SENDER_ID || (appletConfig as Record<string, string>).messagingSenderId || '',
  appId: import.meta.env.VITE_FIREBASE_APP_ID || (appletConfig as Record<string, string>).appId || ''
};

// Initialize Firebase app safely
export const app = !getApps().length ? initializeApp(firebaseConfig) : getApp();
export const db = getFirestore(app, firebaseConfig.firestoreDatabaseId || '(default)');
export const auth = getAuth(app);
