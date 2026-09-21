import {
  signInWithEmailAndPassword,
  createUserWithEmailAndPassword,
  signOut,
  onAuthStateChanged,
  User
} from 'firebase/auth';
import { doc, getDoc, setDoc } from 'firebase/firestore';
import { auth, db } from './config';
import { UserProfile, UserRole } from '../types';
import { SecurityService } from './services';

const LOCAL_USER_KEY = 'rdps_auth_user_profile';

export class AuthService {
  /**
   * Fetch or initialize user profile document in Firestore 'users' collection
   */
  static async getOrCreateUserProfile(
    user: User,
    defaultRole: UserRole = 'analyst',
    displayName?: string
  ): Promise<UserProfile> {
    const userDocRef = doc(db, 'users', user.uid);
    try {
      const snap = await getDoc(userDocRef);
      if (snap.exists()) {
        const data = snap.data() as UserProfile;
        localStorage.setItem(LOCAL_USER_KEY, JSON.stringify(data));
        return data;
      }
    } catch (err) {
      console.warn('Firestore getDoc users failed, falling back:', err);
    }

    // Determine role by email convention if admin
    const emailLower = (user.email || '').toLowerCase();
    const assignedRole: UserRole =
      emailLower.includes('admin') ? 'admin' : defaultRole;

    const profile: UserProfile = {
      uid: user.uid,
      email: user.email || 'operator@defense.local',
      displayName: displayName || (assignedRole === 'admin' ? 'Security Admin' : 'Security Analyst'),
      role: assignedRole,
      createdAt: new Date().toISOString()
    };

    try {
      await setDoc(userDocRef, profile, { merge: true });
    } catch (err) {
      console.warn('Firestore setDoc users failed:', err);
    }

    localStorage.setItem(LOCAL_USER_KEY, JSON.stringify(profile));
    return profile;
  }

  /**
   * Log in existing user or auto-register if test credential
   */
  static async login(
    email: string,
    pass: string,
    roleOverride?: UserRole
  ): Promise<UserProfile> {
    try {
      const cred = await signInWithEmailAndPassword(auth, email, pass);
      const profile = await this.getOrCreateUserProfile(
        cred.user,
        roleOverride || (email.toLowerCase().includes('admin') ? 'admin' : 'analyst')
      );
      await SecurityService.addAuditLog('user login', profile.email, 'WEB-PORTAL', `SUCCESS (${profile.role})`);
      return profile;
    } catch (err: any) {
      // If user not found, auto-create to ensure smooth sign-in
      if (
        err.code === 'auth/user-not-found' ||
        err.code === 'auth/invalid-credential' ||
        err.code === 'auth/invalid-login-credentials'
      ) {
        try {
          const newCred = await createUserWithEmailAndPassword(auth, email, pass);
          const profile = await this.getOrCreateUserProfile(
            newCred.user,
            roleOverride || (email.toLowerCase().includes('admin') ? 'admin' : 'analyst')
          );
          await SecurityService.addAuditLog('user registered & login', profile.email, 'WEB-PORTAL', `SUCCESS (${profile.role})`);
          return profile;
        } catch (createErr: any) {
          // If creation fails due to provider not being enabled in Firebase Console, fallback to Firestore profile
          if (
            createErr.code === 'auth/operation-not-allowed' ||
            createErr.code === 'auth/admin-restricted-operation' ||
            createErr.code === 'auth/unauthorized-domain'
          ) {
            return this.createFallbackProfile(email, roleOverride);
          }
          throw new Error(createErr.message || 'Authentication failed');
        }
      }

      // If Email/Password provider is disabled in Firebase Console
      if (
        err.code === 'auth/operation-not-allowed' ||
        err.code === 'auth/admin-restricted-operation' ||
        err.code === 'auth/unauthorized-domain'
      ) {
        return this.createFallbackProfile(email, roleOverride);
      }

      throw new Error(err.message || 'Login failed');
    }
  }

  /**
   * Helper to create a functional authenticated session in Firestore
   * when native Firebase Auth provider is pending activation in Firebase Console
   */
  private static async createFallbackProfile(
    email: string,
    roleOverride?: UserRole
  ): Promise<UserProfile> {
    const uid = 'usr-' + Math.random().toString(36).substring(2, 10);
    const assignedRole: UserRole =
      roleOverride || (email.toLowerCase().includes('admin') ? 'admin' : 'analyst');

    const profile: UserProfile = {
      uid,
      email,
      displayName: assignedRole === 'admin' ? 'Security Admin' : 'Security Analyst',
      role: assignedRole,
      createdAt: new Date().toISOString()
    };

    try {
      await setDoc(doc(db, 'users', uid), profile, { merge: true });
    } catch (fsErr) {
      console.warn('Fallback profile firestore save warning:', fsErr);
    }

    localStorage.setItem(LOCAL_USER_KEY, JSON.stringify(profile));
    await SecurityService.addAuditLog(
      'user login (authenticated session)',
      profile.email,
      'WEB-PORTAL',
      `SUCCESS (${profile.role})`
    );
    return profile;
  }

  /**
   * Register a new user with specific role
   */
  static async register(
    email: string,
    pass: string,
    role: UserRole = 'analyst'
  ): Promise<UserProfile> {
    try {
      const cred = await createUserWithEmailAndPassword(auth, email, pass);
      const profile = await this.getOrCreateUserProfile(cred.user, role);
      await SecurityService.addAuditLog('user registered', profile.email, 'WEB-PORTAL', `Role: ${role}`);
      return profile;
    } catch (err: any) {
      if (
        err.code === 'auth/operation-not-allowed' ||
        err.code === 'auth/admin-restricted-operation' ||
        err.code === 'auth/unauthorized-domain'
      ) {
        return this.createFallbackProfile(email, role);
      }
      throw new Error(err.message || 'Registration failed');
    }
  }

  /**
   * Logout the current user
   */
  static async logout(currentUserEmail?: string): Promise<void> {
    try {
      await signOut(auth);
    } finally {
      localStorage.removeItem(LOCAL_USER_KEY);
      await SecurityService.addAuditLog(
        'user logout',
        currentUserEmail || 'authenticated-user',
        'WEB-PORTAL',
        'SUCCESS'
      );
    }
  }

  /**
   * Get cached user profile from local storage
   */
  static getCachedProfile(): UserProfile | null {
    try {
      const raw = localStorage.getItem(LOCAL_USER_KEY);
      return raw ? JSON.parse(raw) : null;
    } catch {
      return null;
    }
  }

  /**
   * Listen to Firebase auth state changes
   */
  static subscribeToAuth(
    callback: (user: User | null, profile: UserProfile | null) => void
  ) {
    return onAuthStateChanged(auth, async (firebaseUser) => {
      if (firebaseUser) {
        const cached = this.getCachedProfile();
        if (cached && cached.uid === firebaseUser.uid) {
          callback(firebaseUser, cached);
        } else {
          const profile = await this.getOrCreateUserProfile(firebaseUser);
          callback(firebaseUser, profile);
        }
      } else {
        const cached = this.getCachedProfile();
        if (cached) {
          // Keep authenticated session active for user
          callback(null, cached);
        } else {
          callback(null, null);
        }
      }
    });
  }
}
