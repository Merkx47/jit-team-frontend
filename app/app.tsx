"use client"

import type React from "react"
import Papa from 'papaparse'
import * as XLSX from 'xlsx'
import { useState, useEffect, useRef } from "react"
import {
  Shield,
  Clock,
  User,
  Users,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Settings,
  Eye,
  Plus,
  Search,
  Download,
  Trash2,
  Bell,
  Upload,
  Activity,
  BarChart3,
  ChevronDown,
  ChevronUp,
  RefreshCw,
  Calendar,
  FileText,
  UserCheck,
  AlertCircle,
  X,
  RotateCcw,
  Zap,
  Timer,
  LogOut,
  LogIn,
  Mail,
  UserPlus,
  Copy,
  EyeOff,
  Cloud,
} from "lucide-react"

// Type Definitions
interface ApiConfig {
  BASE_URL: string
  TIMEOUT: number
  HEADERS: {
    "Content-Type": string
    Accept: string
  }
}

interface Permission {
  id: string
  label: string
  description: string
  category: string
  risk: string
  icon: string
}

interface UserType {
  user_id: string
  email: string
  first_name: string
  last_name: string
  role: string  // This should contain the specialized roles like "security_engineer", etc.
  is_active: boolean
  created_at: string
  last_login?: string
}

interface AuthState {
  isAuthenticated: boolean
  user: UserType | null
  token: string | null
}

interface LoginForm {
  email: string
  password: string
}
// 
interface RequestForm {
  email: string
  permissions: string[]
  duration_minutes: number
  justification: string
  urgency: string
  account_id: string
}

interface Notification {
  id: number
  message: string
  type: "success" | "error"
}

interface ConnectionStatus {
  isConnected: boolean
  lastChecked: string | null
}

interface StatusData {
  active: any[]
  pending: any[]
  summary: {
    active: number
    pending: number
    urgent: number
  }
}

interface Role {
  role_id: string
  display_name: string
  description: string
  category: string
  icon: string
  is_admin: boolean
}

interface NavItem {
  id: string
  label: string
  icon: any
  badge?: number
}

// Add these new interfaces to your existing type definitions
interface ForgotPasswordForm {
  email: string
}

interface ResetPasswordForm {
  token: string
  newPassword: string
  confirmPassword: string
}

interface ChangePasswordForm {
  currentPassword: string
  newPassword: string
  confirmPassword: string
}

interface EnhancedPermissionRequest {
  email: string
  duration_minutes: number
  justification: string
  urgency: string
  account_id: string
  use_role_permissions?: boolean
}

interface Permission {
  id: string
  label: string
  description: string
  category: string
  risk: string
  icon: string
  aws_service?: string
}

interface Role {
  role_id: string
  display_name: string
  description: string
  category: string
  icon: string
  is_admin: boolean
}

// API Configuration
const API_CONFIG: ApiConfig = {
  // Your deployed Lambda URL
  BASE_URL: "https://a4xkqqqbgxn5egjelphs6dozdy0zxmle.lambda-url.us-east-1.on.aws",

  // For local development, uncomment this:
  // BASE_URL: 'http://localhost:8000',

  TIMEOUT: 300000, // 5 minutes
  HEADERS: {
    "Content-Type": "application/json",
    Accept: "application/json",
  },
}

// Auth utilities
const getAuthToken = (): string | null => {
  return localStorage.getItem("jit_auth_token")
}

const setAuthToken = (token: string): void => {
  localStorage.setItem("jit_auth_token", token)
}

const removeAuthToken = (): void => {
  localStorage.removeItem("jit_auth_token")
}

// Enhanced API call function with authentication
const apiCall = async (endpoint: string, data: any = null, method = "POST", requireAuth = true): Promise<any> => {
  const url = `${API_CONFIG.BASE_URL}${endpoint}`

  console.log(`🌐 API Call: ${method} ${url}`, data ? { data } : "")

  try {
    const config: RequestInit = {
      method,
      headers: { ...API_CONFIG.HEADERS },
    }

    // ✅ CRITICAL FIX: Handle FormData differently
    const isFormData = data instanceof FormData

    // If it's FormData, don't set Content-Type (let browser handle it)
    if (isFormData) {
      // Remove Content-Type from headers for FormData
      const { 'Content-Type': _, ...headersWithoutContentType } = config.headers as any
      config.headers = headersWithoutContentType
      console.log(`📁 FormData detected - removed Content-Type header`)
    }

    // Add authentication header if required and token exists
    if (requireAuth) {
      const token = getAuthToken()
      if (token) {
        config.headers = {
          ...config.headers,
          Authorization: `Bearer ${token}`,
        }
      }
    }

    if (data && (method === "POST" || method === "PUT")) {
      // ✅ CRITICAL FIX: Don't JSON.stringify FormData
      if (isFormData) {
        config.body = data  // Pass FormData directly
        console.log(`📁 Using FormData as body`)
      } else {
        config.body = JSON.stringify(data)  // JSON.stringify for regular data
        console.log(`📄 Using JSON as body`)
      }
    }

    const controller = new AbortController()
    const timeoutId = setTimeout(() => controller.abort(), API_CONFIG.TIMEOUT)
    config.signal = controller.signal

    const response = await fetch(url, config)
    clearTimeout(timeoutId)

    console.log(`📡 Response Status: ${response.status}`)

    if (!response.ok) {
      const errorText = await response.text()
      console.error(`❌ API Error: ${response.status} - ${errorText}`)

      let errorData: any
      try {
        errorData = JSON.parse(errorText)
      } catch {
        errorData = {
          status: "ERROR",
          message: `HTTP ${response.status}: ${response.statusText}`,
          details: errorText,
        }
      }

      // Handle authentication errors
      if (response.status === 401) {
        removeAuthToken()
        window.location.reload()
        throw new Error("Your session has expired. Please log in again.")
      }

      // Enhanced user-friendly error messages based on status code and content
      let friendlyMessage = getFriendlyErrorMessage(response.status, errorData, endpoint)
      
      throw new Error(friendlyMessage)
    }

    const result = await response.json()
    console.log(`✅ API Success:`, result)
    return result
  } catch (error: any) {
    if (error.name === "AbortError") {
      console.error("🕐 Request timeout")
      throw new Error("Request timed out. Please check your connection and try again.")
    }

    console.error(`💥 API Call Failed:`, error)

    // Network error handling
    if (!navigator.onLine) {
      throw new Error("No internet connection. Please check your network and try again.")
    }

    // Re-throw the error as-is (it already has a good message from above)
    throw error
  }
}


// Helper function for user-friendly error messages
const getFriendlyErrorMessage = (status: number, errorData: any, endpoint: string): string => {
  // Properly extract the message from nested error structures
  let originalMessage = ""
  
  if (typeof errorData === "string") {
    originalMessage = errorData
  } else if (errorData?.detail?.message) {
    // Handle nested structure like {"detail":{"message":"Status check failed"}}
    originalMessage = errorData.detail.message
  } else if (errorData?.message) {
    originalMessage = errorData.message
  } else if (typeof errorData?.detail === "string") {
    originalMessage = errorData.detail
  } else {
    originalMessage = ""
  }
 
  // Handle specific error cases with user-friendly messages
  if (originalMessage.includes("User with this email already exists")) {
    return "This email address already has an account. Please use the login form instead."
  }
 
  if (originalMessage.includes("Invalid email or password") || originalMessage.includes("Invalid credentials")) {
    return "The email or password you entered is incorrect. Please check your credentials and try again."
  }
 
  if (originalMessage.includes("User not found")) {
    return "No account found with this email address. Please check the email or contact your administrator for an invitation."
  }
 
  if (originalMessage.includes("Account is disabled") || originalMessage.includes("not active")) {
    return "Your account has been disabled. Please contact your administrator for assistance."
  }
 
  if (originalMessage.includes("Admin access required") || originalMessage.includes("permission")) {
    return "You don't have permission to perform this action. Contact your administrator if you believe this is an error."
  }
 
  if (originalMessage.includes("Invalid signup token") || originalMessage.includes("expired")) {
    return "This invitation link has expired or is invalid. Please request a new invitation from your administrator."
  }
 
  if (originalMessage.includes("AWS account")) {
    if (originalMessage.includes("not found")) {
      return "The selected AWS account is no longer available. Please choose a different account."
    }
    if (originalMessage.includes("not active")) {
      return "The selected AWS account is currently inactive. Please choose a different account."
    }
  }
 
  if (originalMessage.includes("Account number must be exactly 12 digits")) {
    return "AWS account number must be exactly 12 digits. Please check the account number and try again."
  }
 
  if (originalMessage.includes("already exists") && endpoint.includes("aws-accounts")) {
    return "An AWS account with this number already exists in the system."
  }
 
  if (originalMessage.includes("rate limit") || originalMessage.includes("too many")) {
    return "Too many requests. Please wait a few minutes before trying again."
  }
 
  if (originalMessage.includes("validation") || originalMessage.includes("invalid data")) {
    return "Please check your information and make sure all required fields are filled out correctly."
  }

  // Handle the specific "Status check failed" error
  if (originalMessage.includes("Status check failed")) {
    return "Unable to load request status. Please refresh the page or try again in a moment."
  }
 
  // Status code based messages
  switch (status) {
    case 400:
      return originalMessage || "Invalid request. Please check your information and try again."
    case 403:
      return "You don't have permission to perform this action."
    case 404:
      return "The requested resource was not found. It may have been deleted or moved."
    case 409:
      return originalMessage || "This action conflicts with existing data. Please check and try again."
    case 422:
      return "The information provided is invalid. Please check all fields and try again."
    case 429:
      return "Too many requests. Please wait a moment and try again."
    case 500:
      return "Server error. Please try again later or contact support if the problem persists."
    case 502:
    case 503:
    case 504:
      return "Service is temporarily unavailable. Please try again in a few moments."
    default:
      return originalMessage || `Something went wrong (Error ${status}). Please try again or contact support.`
  }
}

// Constants
const PERMISSIONS: Permission[] = [
  {
    id: "S3_READ",
    label: "S3 Read Access",
    description: "Read files from S3 buckets",
    category: "Storage",
    risk: "low",
    icon: "📁",
  },
  {
    id: "S3_WRITE",
    label: "S3 Write Access",
    description: "Upload/modify files in S3 buckets",
    category: "Storage",
    risk: "medium",
    icon: "📝",
  },
  {
    id: "S3_FULL_CONTROL",
    label: "S3 Full Control",
    description: "Complete S3 bucket management",
    category: "Storage",
    risk: "high",
    icon: "🗂️",
  },
  {
    id: "EC2_READ",
    label: "EC2 Read Access",
    description: "View EC2 instances and settings",
    category: "Compute",
    risk: "low",
    icon: "🖥️",
  },
  {
    id: "EC2_WRITE",
    label: "EC2 Write Access",
    description: "Start/stop/modify EC2 instances",
    category: "Compute",
    risk: "high",
    icon: "⚡",
  },
  {
    id: "EC2_SECURITY",
    label: "EC2 Security",
    description: "Manage security groups and key pairs",
    category: "Compute",
    risk: "high",
    icon: "🔒",
  },
  {
    id: "LAMBDA_READ",
    label: "Lambda Read Access",
    description: "View Lambda functions",
    category: "Serverless",
    risk: "low",
    icon: "λ",
  },
  {
    id: "LAMBDA_WRITE",
    label: "Lambda Write Access",
    description: "Create/modify Lambda functions",
    category: "Serverless",
    risk: "high",
    icon: "🔧",
  },
  {
    id: "LAMBDA_INVOKE",
    label: "Lambda Invoke",
    description: "Execute Lambda functions",
    category: "Serverless",
    risk: "medium",
    icon: "🚀",
  },
  {
    id: "RDS_READ",
    label: "RDS Read Access",
    description: "View RDS databases",
    category: "Database",
    risk: "low",
    icon: "🗃️",
  },
  {
    id: "RDS_WRITE",
    label: "RDS Write Access",
    description: "Manage RDS databases",
    category: "Database",
    risk: "high",
    icon: "🔨",
  },
]

const QUICK_DURATIONS = [
  { minutes: 60, label: "1 hour", recommended: true },
  { minutes: 120, label: "2 hours", recommended: true },
  { minutes: 240, label: "4 hours", recommended: false },
  { minutes: 480, label: "8 hours", recommended: false },
]

// Update your global getRoleDisplayName function
const getRoleDisplayName = (role: string, availableRoles: Role[] = []): string => {
  // Try to find the role in loaded data first
  const foundRole = availableRoles.find(r => r.role_id === role)
  if (foundRole) {
    console.log(`Found dynamic role: ${role} -> ${foundRole.display_name}`)
    return foundRole.display_name
  }
  
  // Fallback to hardcoded mapping
  const roleNames: {[key: string]: string} = {
    'user': 'Basic User',
    'admin': 'Administrator',
    'database_administrator': 'Database Administrator',
    'system_administrator': 'System Administrator',
    'frontend_engineer': 'Frontend Engineer',
    'backend_engineer': 'Backend Engineer',
    'network_engineer': 'Network Engineer',
    'ml_engineer': 'ML Engineer',
    'security_engineer': 'Security Engineer',
    'devops_engineer': 'DevOps Engineer',
    'data_engineer': 'Data Engineer',
    'super_administrator': 'Super Administrator'
  }
  
  console.log(`Using fallback role mapping: ${role} -> ${roleNames[role] || role}`)
  return roleNames[role] || role.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())
}

const getRoleIcon = (role: string): string => {
  const roleIcons: {[key: string]: string} = {
    'user': '👤',
    'admin': '👑',
    'database_administrator': '🗄️',
    'system_administrator': '⚙️',
    'frontend_engineer': '🎨',
    'backend_engineer': '🔧',
    'network_engineer': '🌐',
    'ml_engineer': '🤖',
    'security_engineer': '🛡️',
    'devops_engineer': '🚀',
    'data_engineer': '📊',
    'super_administrator': '🔥'
  }
  return roleIcons[role] || '👤'
}

const isAdminRole = (role: string): boolean => {
  const adminRoles = [
    'admin', 
    'super_administrator', 
    'system_administrator', 
    'security_engineer'
  ]
  return adminRoles.includes(role)
}

// Utility Functions
const formatTimeRemaining = (seconds: number): string => {
  if (!seconds) return "N/A"
  const hours = Math.floor(seconds / 3600)
  const minutes = Math.floor((seconds % 3600) / 60)
  return `${hours}h ${minutes}m`
}

const getStatusColor = (status: string): string => {
  switch (status) {
    case "PENDING":
      return "bg-yellow-100 text-yellow-800 border-yellow-200"
    case "APPROVED":
      return "bg-blue-100 text-blue-800 border-blue-200"
    case "ACTIVE":
      return "bg-green-100 text-green-800 border-green-200"
    case "DENIED":
      return "bg-red-100 text-red-800 border-red-200"
    case "REVOKED":
      return "bg-gray-100 text-gray-800 border-gray-200"
    default:
      return "bg-gray-100 text-gray-800 border-gray-200"
  }
}

const getRiskColor = (risk: string): string => {
  switch (risk) {
    case "low":
      return "text-green-600 bg-green-50"
    case "medium":
      return "text-yellow-600 bg-yellow-50"
    case "high":
      return "text-red-600 bg-red-50"
    default:
      return "text-gray-600 bg-gray-50"
  }
}

const getUrgencyColor = (urgency: string): string => {
  switch (urgency) {
    case "low":
      return "bg-blue-100 text-blue-800"
    case "normal":
      return "bg-gray-100 text-gray-800"
    case "high":
      return "bg-orange-100 text-orange-800"
    case "critical":
      return "bg-red-100 text-red-800"
    default:
      return "bg-gray-100 text-gray-800"
  }
}

// Login Component with Built-in Error Handling
const LoginForm: React.FC<{
  loginForm: LoginForm
  setLoginForm: React.Dispatch<React.SetStateAction<LoginForm>>
  loading: boolean
  handleLogin: () => Promise<void> | void
}> = ({ loginForm, setLoginForm, loading, handleLogin }) => {
  const [showPassword, setShowPassword] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [attemptCount, setAttemptCount] = useState(0)
  const [showForgotPassword, setShowForgotPassword] = useState(false)
  const [notifications, setNotifications] = useState<Notification[]>([])

  const addNotification = (message: string, type: "success" | "error") => {
    const id = Date.now()
    setNotifications((prev) => [...prev, { id, message, type }])
    setTimeout(() => {
      setNotifications((prev) => prev.filter((n) => n.id !== id))
    }, 5000)
  }

  const handleLoginSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)
    
    try {
      await handleLogin()
      setAttemptCount(0)
    } catch (err: any) {
      setAttemptCount(prev => prev + 1)
      
      if (err.message?.includes('Invalid credentials') || err.message?.includes('Unauthorized')) {
        setError('Invalid email or password. Please check your credentials and try again.')
      } else if (err.message?.includes('User not found')) {
        setError('No account found with this email address.')
      } else if (err.message?.includes('Account locked') || attemptCount >= 3) {
        setError('Account temporarily locked due to multiple failed attempts. Contact your administrator.')
      } else if (err.message?.includes('Network')) {
        setError('Connection error. Please check your internet connection and try again.')
      } else {
        setError('Login failed. Please try again or contact support if the problem persists.')
      }
    }
  }

  const handleInputChange = (field: 'email' | 'password', value: string) => {
    if (error) {
      setError(null)
    }
    setLoginForm((prev) => ({ ...prev, [field]: value }))
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 flex items-center justify-center px-4">
      <Notifications notifications={notifications} />
      
      <div className="max-w-md w-full bg-white rounded-2xl shadow-xl p-8">
        <div className="text-center mb-8">
          <div className="p-3 bg-blue-100 rounded-xl inline-block mb-4">
            <Shield className="w-12 h-12 text-blue-600" />
          </div>
          <h1 className="text-3xl font-bold bg-gradient-to-r from-blue-600 to-purple-600 bg-clip-text text-transparent">
            QTEAM System
          </h1>
          <p className="text-gray-600 mt-2">Qucoon Temporary Elevated Access Management</p>
        </div>

        {error && (
          <div className="mb-6 p-4 bg-red-50 border border-red-200 rounded-lg animate-in slide-in-from-top-2 duration-300">
            <div className="flex items-start">
              <AlertCircle className="w-5 h-5 text-red-500 mt-0.5 mr-3 flex-shrink-0" />
              <div className="flex-1">
                <p className="text-sm text-red-800 font-medium">Authentication Failed</p>
                <p className="text-sm text-red-700 mt-1">{error}</p>
                {attemptCount > 1 && (
                  <p className="text-xs text-red-600 mt-2">
                    Attempt {attemptCount} of 5
                  </p>
                )}
              </div>
              <button
                onClick={() => setError(null)}
                className="text-red-400 hover:text-red-600 transition-colors"
                aria-label="Dismiss error"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
          </div>
        )}

        {!error && !loading && attemptCount === 0 && loginForm.email && loginForm.password && (
          <div className="mb-6 p-3 bg-green-50 border border-green-200 rounded-lg">
            <div className="flex items-center">
              <CheckCircle className="w-4 h-4 text-green-500 mr-2" />
              <p className="text-sm text-green-800">Ready to sign in</p>
            </div>
          </div>
        )}

        <form onSubmit={handleLoginSubmit} className="space-y-6">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Email Address</label>
            <input
              type="email"
              value={loginForm.email}
              onChange={(e) => handleInputChange('email', e.target.value)}
              placeholder="Enter your email"
              className={`w-full px-4 py-3 border rounded-lg focus:ring-2 transition-all duration-200 ${
                error 
                  ? 'border-red-300 bg-red-50 focus:ring-red-500 focus:border-red-500' 
                  : 'border-gray-300 focus:ring-blue-500 focus:border-blue-500'
              }`}
              required
              autoComplete="email"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Password</label>
            <div className="relative">
              <input
                type={showPassword ? "text" : "password"}
                value={loginForm.password}
                onChange={(e) => handleInputChange('password', e.target.value)}
                placeholder="Enter your password"
                className={`w-full px-4 py-3 pr-12 border rounded-lg focus:ring-2 transition-all duration-200 ${
                  error 
                    ? 'border-red-300 bg-red-50 focus:ring-red-500 focus:border-red-500' 
                    : 'border-gray-300 focus:ring-blue-500 focus:border-blue-500'
                }`}
                required
                autoComplete="current-password"
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="absolute inset-y-0 right-0 px-3 flex items-center text-gray-400 hover:text-gray-600 focus:outline-none transition-colors"
                aria-label={showPassword ? "Hide password" : "Show password"}
              >
                {!showPassword ? (
                  <EyeOff className="w-5 h-5" />
                ) : (
                  <Eye className="w-5 h-5" />
                )}
              </button>
            </div>
          </div>

          <div className="flex items-center justify-between">
            <div className="text-sm">
              <button
                type="button"
                onClick={() => setShowForgotPassword(true)}
                className="text-blue-600 hover:text-blue-800 font-medium"
              >
                Forgot your password?
              </button>
            </div>
          </div>

          <button
            type="submit"
            disabled={loading || attemptCount >= 5}
            className={`w-full py-3 px-4 rounded-lg font-medium transition-all duration-200 flex items-center justify-center space-x-2 ${
              loading || attemptCount >= 5
                ? 'bg-gray-400 text-white cursor-not-allowed'
                : error
                ? 'bg-red-600 text-white hover:bg-red-700'
                : 'bg-blue-600 text-white hover:bg-blue-700'
            }`}
          >
            {loading ? (
              <>
                <RefreshCw className="w-4 h-4 animate-spin" />
                <span>Signing in...</span>
              </>
            ) : attemptCount >= 5 ? (
              <>
                <Shield className="w-4 h-4" />
                <span>Account Locked</span>
              </>
            ) : error ? (
              <>
                <RotateCcw className="w-4 h-4" />
                <span>Try Again</span>
              </>
            ) : (
              <>
                <LogIn className="w-4 h-4" />
                <span>Sign In</span>
              </>
            )}
          </button>
        </form>

        <div className="mt-6 text-center">
          <p className="text-sm text-gray-600">
            Need an account? Contact your administrator for an invitation.
          </p>
          {attemptCount > 2 && (
            <p className="text-xs text-red-600 mt-2">
              Having trouble? Contact support at support@qucoon.com
            </p>
          )}
        </div>
      </div>

      <ForgotPasswordModal
        isOpen={showForgotPassword}
        onClose={() => setShowForgotPassword(false)}
        addNotification={addNotification}
      />
    </div>
  )
}

// Token-based Signup Component
const TokenSignupForm: React.FC<{
  signupForm: any
  setSignupForm: React.Dispatch<React.SetStateAction<any>>
  loading: boolean
  handleSignup: () => void
  tokenEmail: string
}> = ({ signupForm, setSignupForm, loading, handleSignup, tokenEmail }) => {
  const [errors, setErrors] = useState<{[key: string]: string}>({})
  const [showPassword, setShowPassword] = useState(false)
  const [showConfirmPassword, setShowConfirmPassword] = useState(false)

  // Validation functions
  const validateField = (field: string, value: string): string | null => {
    switch (field) {
      case 'first_name':
        if (!value.trim()) return "First name is required"
        if (value.trim().length < 2) return "First name must be at least 2 characters"
        if (!/^[a-zA-Z\s'-]+$/.test(value)) return "First name can only contain letters, spaces, hyphens, and apostrophes"
        return null
        
      case 'last_name':
        if (!value.trim()) return "Last name is required"
        if (value.trim().length < 2) return "Last name must be at least 2 characters"
        if (!/^[a-zA-Z\s'-]+$/.test(value)) return "Last name can only contain letters, spaces, hyphens, and apostrophes"
        return null
        
      case 'password':
        if (!value) return "Password is required"
        if (value.length < 8) return "Password must be at least 8 characters long"
        if (!/(?=.*[a-z])/.test(value)) return "Password must contain at least one lowercase letter"
        if (!/(?=.*[A-Z])/.test(value)) return "Password must contain at least one uppercase letter"
        if (!/(?=.*\d)/.test(value)) return "Password must contain at least one number"
        return null
        
      case 'confirmPassword':
        if (!value) return "Please confirm your password"
        if (value !== signupForm.password) return "Passwords do not match"
        return null
        
      default:
        return null
    }
  }

  const handleFieldChange = (field: string, value: string) => {
    setSignupForm((prev: any) => ({ ...prev, [field]: value }))
    
    // Clear error when user starts typing
    if (errors[field]) {
      setErrors(prev => ({ ...prev, [field]: "" }))
    }
    
    // Also clear confirmPassword error if password changes
    if (field === 'password' && errors.confirmPassword) {
      setErrors(prev => ({ ...prev, confirmPassword: "" }))
    }
  }

  const validateForm = (): boolean => {
    const newErrors: {[key: string]: string} = {}
    
    const fields = ['first_name', 'last_name', 'password', 'confirmPassword']
    fields.forEach(field => {
      const error = validateField(field, signupForm[field] || '')
      if (error) {
        newErrors[field] = error
      }
    })
    
    setErrors(newErrors)
    return Object.keys(newErrors).length === 0
  }

  const handleSignupSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    
    if (validateForm()) {
      handleSignup()
    }
  }

  const getPasswordStrength = (password: string): { strength: number, text: string, color: string } => {
    let strength = 0
    if (password.length >= 8) strength++
    if (/(?=.*[a-z])/.test(password)) strength++
    if (/(?=.*[A-Z])/.test(password)) strength++
    if (/(?=.*\d)/.test(password)) strength++
    if (/(?=.*[!@#$%^&*])/.test(password)) strength++
    
    if (strength <= 2) return { strength, text: "Weak", color: "text-red-600" }
    if (strength <= 3) return { strength, text: "Fair", color: "text-yellow-600" }
    if (strength <= 4) return { strength, text: "Good", color: "text-blue-600" }
    return { strength, text: "Strong", color: "text-green-600" }
  }

  const passwordStrength = getPasswordStrength(signupForm.password || '')

  return (
    <div className="min-h-screen bg-gradient-to-br from-green-50 to-blue-100 flex items-center justify-center px-4">
      <div className="max-w-md w-full bg-white rounded-2xl shadow-xl p-8">
        <div className="text-center mb-8">
          <div className="p-3 bg-green-100 rounded-xl inline-block mb-4">
            <UserPlus className="w-12 h-12 text-green-600" />
          </div>
          <h1 className="text-3xl font-bold bg-gradient-to-r from-green-600 to-blue-600 bg-clip-text text-transparent">
            Complete Your Registration
          </h1>
          <p className="text-gray-600 mt-2">You've been invited to join the QTEAM System</p>
        </div>

        <div className="mb-6 p-4 bg-green-50 rounded-lg border border-green-200">
          <p className="text-sm text-green-800">
            <strong>Invitation for:</strong> {tokenEmail}
          </p>
        </div>

        <form onSubmit={handleSignupSubmit} className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">First Name *</label>
              <input
                type="text"
                value={signupForm.first_name || ''}
                onChange={(e) => handleFieldChange('first_name', e.target.value)}
                placeholder="First name"
                className={`w-full px-4 py-3 border rounded-lg focus:ring-2 transition-colors ${
                  errors.first_name 
                    ? 'border-red-300 focus:ring-red-500 focus:border-red-500' 
                    : 'border-gray-300 focus:ring-green-500 focus:border-green-500'
                }`}
                required
                disabled={loading}
              />
              {errors.first_name && (
                <p className="mt-1 text-sm text-red-600 flex items-center">
                  <AlertCircle className="w-4 h-4 mr-1" />
                  {errors.first_name}
                </p>
              )}
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Last Name *</label>
              <input
                type="text"
                value={signupForm.last_name || ''}
                onChange={(e) => handleFieldChange('last_name', e.target.value)}
                placeholder="Last name"
                className={`w-full px-4 py-3 border rounded-lg focus:ring-2 transition-colors ${
                  errors.last_name 
                    ? 'border-red-300 focus:ring-red-500 focus:border-red-500' 
                    : 'border-gray-300 focus:ring-green-500 focus:border-green-500'
                }`}
                required
                disabled={loading}
              />
              {errors.last_name && (
                <p className="mt-1 text-sm text-red-600 flex items-center">
                  <AlertCircle className="w-4 h-4 mr-1" />
                  {errors.last_name}
                </p>
              )}
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Email Address</label>
            <input
              type="email"
              value={tokenEmail}
              readOnly
              className="w-full px-4 py-3 border border-gray-300 rounded-lg bg-gray-50 text-gray-600"
            />
            <p className="text-xs text-gray-500 mt-1">This email was specified in your invitation</p>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Password *</label>
            <div className="relative">
              <input
                type={showPassword ? "text" : "password"}
                value={signupForm.password || ''}
                onChange={(e) => handleFieldChange('password', e.target.value)}
                placeholder="Create a secure password"
                className={`w-full px-4 py-3 pr-12 border rounded-lg focus:ring-2 transition-colors ${
                  errors.password 
                    ? 'border-red-300 focus:ring-red-500 focus:border-red-500' 
                    : 'border-gray-300 focus:ring-green-500 focus:border-green-500'
                }`}
                required
                disabled={loading}
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="absolute inset-y-0 right-0 px-3 flex items-center text-gray-400 hover:text-gray-600"
              >
                {showPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
              </button>
            </div>
            
            {/* Password strength indicator */}
            {signupForm.password && (
              <div className="mt-2">
                <div className="flex items-center space-x-2">
                  <div className="flex-1 bg-gray-200 rounded-full h-2">
                    <div 
                      className={`h-2 rounded-full transition-all duration-300 ${
                        passwordStrength.strength <= 2 ? 'bg-red-500' :
                        passwordStrength.strength <= 3 ? 'bg-yellow-500' :
                        passwordStrength.strength <= 4 ? 'bg-blue-500' : 'bg-green-500'
                      }`}
                      style={{ width: `${(passwordStrength.strength / 5) * 100}%` }}
                    ></div>
                  </div>
                  <span className={`text-xs font-medium ${passwordStrength.color}`}>
                    {passwordStrength.text}
                  </span>
                </div>
              </div>
            )}
            
            {errors.password && (
              <p className="mt-1 text-sm text-red-600 flex items-center">
                <AlertCircle className="w-4 h-4 mr-1" />
                {errors.password}
              </p>
            )}
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Confirm Password *</label>
            <div className="relative">
              <input
                type={showConfirmPassword ? "text" : "password"}
                value={signupForm.confirmPassword || ''}
                onChange={(e) => handleFieldChange('confirmPassword', e.target.value)}
                placeholder="Confirm your password"
                className={`w-full px-4 py-3 pr-12 border rounded-lg focus:ring-2 transition-colors ${
                  errors.confirmPassword 
                    ? 'border-red-300 focus:ring-red-500 focus:border-red-500' 
                    : signupForm.confirmPassword && signupForm.confirmPassword === signupForm.password
                      ? 'border-green-300 focus:ring-green-500 focus:border-green-500'
                      : 'border-gray-300 focus:ring-green-500 focus:border-green-500'
                }`}
                required
                disabled={loading}
              />
              <button
                type="button"
                onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                className="absolute inset-y-0 right-0 px-3 flex items-center text-gray-400 hover:text-gray-600"
              >
                {showConfirmPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
              </button>
            </div>
            
            {/* Password match indicator */}
            {signupForm.confirmPassword && (
              <div className="mt-1">
                {signupForm.confirmPassword === signupForm.password ? (
                  <p className="text-sm text-green-600 flex items-center">
                    <CheckCircle className="w-4 h-4 mr-1" />
                    Passwords match
                  </p>
                ) : (
                  <p className="text-sm text-red-600 flex items-center">
                    <AlertCircle className="w-4 h-4 mr-1" />
                    Passwords do not match
                  </p>
                )}
              </div>
            )}
            
            {errors.confirmPassword && (
              <p className="mt-1 text-sm text-red-600 flex items-center">
                <AlertCircle className="w-4 h-4 mr-1" />
                {errors.confirmPassword}
              </p>
            )}
          </div>

          <button
            type="submit"
            disabled={loading || Object.keys(errors).length > 0}
            className="w-full bg-green-600 text-white py-3 px-4 rounded-lg font-medium hover:bg-green-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center space-x-2"
          >
            {loading ? (
              <>
                <RefreshCw className="w-4 h-4 animate-spin" />
                <span>Creating account...</span>
              </>
            ) : (
              <>
                <UserPlus className="w-4 h-4" />
                <span>Complete Registration</span>
              </>
            )}
          </button>
        </form>

        <div className="mt-6 p-4 bg-gray-50 rounded-lg">
          <p className="text-xs text-gray-600">
            By creating an account, you agree to follow your organization's access policies and security guidelines.
          </p>
        </div>
      </div>
    </div>
  )
}

// Header Component
const Header: React.FC<{
  authState: AuthState
  statusData: StatusData
  connectionStatus: ConnectionStatus
  handleLogout: () => void
  availableRoles: Role[]
}> = ({ authState, statusData, connectionStatus, handleLogout, availableRoles }) => {
  const [showUserMenu, setShowUserMenu] = useState(false)
  const [showChangePassword, setShowChangePassword] = useState(false)
  const [notifications, setNotifications] = useState<Notification[]>([])

  const addNotification = (message: string, type: "success" | "error") => {
    const id = Date.now()
    setNotifications((prev) => [...prev, { id, message, type }])
    setTimeout(() => {
      setNotifications((prev) => prev.filter((n) => n.id !== id))
    }, 5000)
  }

  return (
    <>
      <Notifications notifications={notifications} />
      
      <header className="bg-white shadow-sm border-b border-gray-200">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center">
              <div className="p-2 bg-blue-100 rounded-xl mr-4">
                <Shield className="w-8 h-8 text-blue-600" />
              </div>
              <div>
                <h1 className="text-xl font-bold bg-gradient-to-r from-blue-600 to-purple-600 bg-clip-text text-transparent">
                  QTEAM
                </h1>
                <p className="text-xs text-gray-500 font-medium">Qucoon Temporary Elevated Access Management</p>
              </div>
            </div>
            
            <div className="flex items-center space-x-6">
              <div className="hidden md:flex items-center space-x-4">
                <div className="text-sm text-gray-600">
                  Welcome back,{" "}
                  <span className="font-semibold text-gray-900">
                    {authState.user?.first_name} {authState.user?.last_name}
                  </span>
                </div>
                <div className="flex items-center text-sm text-gray-500 bg-gray-100 px-3 py-2 rounded-lg">
                  <User className="w-4 h-4 mr-2" />
                  {getRoleDisplayName(authState.user?.role || '', availableRoles)}
                </div>
              </div>
              
              <div className="flex items-center space-x-2">
                <div
                  className={`w-3 h-3 rounded-full ${connectionStatus.isConnected ? "bg-green-500" : "bg-red-500"}`}
                ></div>
                <span className="text-sm text-gray-500">{connectionStatus.isConnected ? "Online" : "Offline"}</span>
              </div>
              
              <button className="p-2 text-gray-400 hover:text-gray-600 relative">
                <Bell className="w-6 h-6" />
                {(statusData.summary.pending > 0 || statusData.summary.urgent > 0) && (
                  <span className="absolute -top-1 -right-1 bg-red-500 text-white text-xs font-medium px-1.5 py-0.5 rounded-full">
                    {statusData.summary.pending + statusData.summary.urgent}
                  </span>
                )}
              </button>

              {/* User Menu */}
              <div className="relative">
                <button
                  onClick={() => setShowUserMenu(!showUserMenu)}
                  className="flex items-center space-x-2 text-gray-600 hover:text-gray-800 px-3 py-2 rounded-lg hover:bg-gray-100 transition-colors"
                >
                  <div className="w-8 h-8 bg-blue-100 rounded-full flex items-center justify-center">
                    <span className="text-sm font-medium text-blue-600">
                      {authState.user?.first_name?.[0]}{authState.user?.last_name?.[0]}
                    </span>
                  </div>
                  <ChevronDown className="w-4 h-4" />
                </button>

                {showUserMenu && (
                  <div className="absolute right-0 mt-2 w-64 bg-white rounded-md shadow-lg py-1 z-50 border border-gray-200">
                    <div className="px-4 py-2 text-sm text-gray-700 border-b border-gray-100">
                      <div className="font-medium truncate">{authState.user?.first_name} {authState.user?.last_name}</div>
                      <div className="text-gray-500 text-xs break-all">{authState.user?.email}</div>
                    </div>
                    
                    <button
                      onClick={() => {
                        setShowChangePassword(true)
                        setShowUserMenu(false)
                      }}
                      className="block w-full text-left px-4 py-2 text-sm text-gray-700 hover:bg-gray-100"
                    >
                      Change Password
                    </button>
                    
                    <button
                      onClick={() => {
                        handleLogout()
                        setShowUserMenu(false)
                      }}
                      className="block w-full text-left px-4 py-2 text-sm text-gray-700 hover:bg-gray-100"
                    >
                      <div className="flex items-center">
                        <LogOut className="w-4 h-4 mr-2" />
                        Sign Out
                      </div>
                    </button>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      </header>

      <ChangePasswordModal
        isOpen={showChangePassword}
        onClose={() => setShowChangePassword(false)}
        addNotification={addNotification}
      />
    </>
  )
}

// Navigation Component
const Navigation: React.FC<{
  activeTab: string
  setActiveTab: React.Dispatch<React.SetStateAction<string>>
  authState: AuthState
  statusData: StatusData
}> = ({ activeTab, setActiveTab, authState, statusData }) => {
  const getNavItems = (): NavItem[] => {
    const baseItems: NavItem[] = [{ id: "dashboard", label: "Dashboard", icon: BarChart3 }]

    if (authState.user?.role === "user") {
      return [
        { id: "request", label: "New Request", icon: Plus },
        { id: "my-requests", label: "My Requests", icon: Eye },
      ]
    }

    if (isAdminRole(authState.user?.role || '')) {
      return [
        ...baseItems,
        { id: "admin", label: "Administration", icon: Settings },
        { 
          id: "approvals", 
          label: "All Requests", 
          icon: Users,
          ...(statusData.summary.pending > 0 && { badge: statusData.summary.pending })
        },
        { id: "invitations", label: "User Invitations", icon: Mail },
        { id: "aws-accounts", label: "AWS Accounts", icon: Cloud },
      ]
    }

    return baseItems
  }

  return (
    <nav className="bg-white shadow-sm border border-gray-200 rounded-xl mb-6">
      <div className="flex overflow-x-auto">
        {getNavItems().map((item) => (
          <button
            key={item.id}
            onClick={() => setActiveTab(item.id)}
            className={`flex items-center px-6 py-4 text-sm font-medium whitespace-nowrap relative transition-all ${
              activeTab === item.id
                ? "text-blue-600 border-b-2 border-blue-600 bg-blue-50"
                : "text-gray-500 hover:text-gray-700 hover:bg-gray-50"
            }`}
          >
            <item.icon className="w-5 h-5 mr-2" />
            {item.label}
            {item.badge && item.badge > 0 && (
              <span className="ml-2 bg-red-500 text-white text-xs font-medium px-2 py-1 rounded-full">
                {item.badge}
              </span>
            )}
          </button>
        ))}
      </div>
    </nav>
  )
}

// Notifications Component
const Notifications: React.FC<{ notifications: Notification[] }> = ({ notifications }) => (
  <div className="fixed top-4 right-4 space-y-3 z-50 max-w-sm">
    {notifications.map((notification) => (
      <div
        key={notification.id}
        className={`p-4 rounded-xl shadow-lg border transition-all transform ${
          notification.type === "success"
            ? "bg-green-50 text-green-800 border-green-200"
            : "bg-red-50 text-red-800 border-red-200"
        } animate-slide-in`}
      >
        <div className="flex items-start">
          {notification.type === "success" ? (
            <CheckCircle className="w-5 h-5 mr-3 mt-0.5 text-green-600 flex-shrink-0" />
          ) : (
            <XCircle className="w-5 h-5 mr-3 mt-0.5 text-red-600 flex-shrink-0" />
          )}
          <div className="text-sm leading-relaxed whitespace-pre-line">{notification.message}</div>
        </div>
      </div>
    ))}
  </div>
)



// Enhanced User Invitations Component with CSV-Only Bulk Upload Support
const UserInvitations: React.FC<{
  addNotification: (message: string, type: "success" | "error") => void
}> = ({ addNotification }) => {
  // Existing single invitation state
  const [inviteEmail, setInviteEmail] = useState("")
  const [inviteRole, setInviteRole] = useState("user")
  const [loading, setLoading] = useState(false)
  const [generatedLink, setGeneratedLink] = useState("")
  const [errors, setErrors] = useState<{[key: string]: string}>({})

  // Bulk upload state
  const [showBulkUpload, setShowBulkUpload] = useState(false)
  const [bulkFile, setBulkFile] = useState<File | null>(null)
  const [bulkLoading, setBulkLoading] = useState(false)
  const [bulkResults, setBulkResults] = useState<any>(null)
  const [parsedData, setParsedData] = useState<any[]>([])
  const [dragActive, setDragActive] = useState(false)
  const [uploadProgress, setUploadProgress] = useState(0)
  const [detectedColumns, setDetectedColumns] = useState<{
    emailField: string | null
    roleField: string | null
  }>({ emailField: null, roleField: null })

  // File input ref
  const fileInputRef = useRef<HTMLInputElement>(null)

  // Email validation function
  const validateEmail = (email: string): string | null => {
    if (!email.trim()) {
      return "Email address is required"
    }
    
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
    if (!emailRegex.test(email)) {
      return "Please enter a valid email address"
    }
    
    if (email.length > 254) {
      return "Email address is too long"
    }
    
    return null
  }

  // Role normalization function - maps various role names to 'user' or 'admin'
  const normalizeRole = (roleValue: string): string | null => {
    if (!roleValue) return 'user'
    
    const normalized = roleValue.toString().trim().toLowerCase()
    
    // Admin variations
    const adminRoles = [
      'admin', 'administrator', 'manager', 'supervisor', 'lead', 'owner', 
      'root', 'super', 'superuser', 'super user', 'superadmin', 'super admin',
      'moderator', 'mod', 'director', 'head', 'chief', 'principal'
    ]
    
    // User variations (everything else defaults to user anyway)
    const userRoles = [
      'user', 'member', 'employee', 'staff', 'worker', 'contributor',
      'viewer', 'guest', 'reader', 'editor', 'standard', 'basic',
      'regular', 'normal', 'standard user', 'end user', 'enduser'
    ]
    
    // Check for admin roles first
    if (adminRoles.includes(normalized)) {
      return 'admin'
    }
    
    // Check for user roles or default to user
    if (userRoles.includes(normalized)) {
      return 'user'
    }
    
    // If it contains "admin" anywhere in the string
    if (normalized.includes('admin') || normalized.includes('manager') || normalized.includes('super')) {
      return 'admin'
    }
    
    // If we can't recognize it but it's not empty, default to user
    if (normalized.length > 0) {
      return 'user'
    }
    
    return null
  }

  // Smart email detection by analyzing actual data values
  const detectEmailAndRoleColumns = (data: any[]): { emailField: string | null, roleField: string | null } => {
    if (data.length === 0) return { emailField: null, roleField: null }
    
    const firstRow = data[0]
    const headers = Object.keys(firstRow)
    
    let emailField: string | null = null
    let roleField: string | null = null
    
    // Check each column to see if it contains email-like values
    for (const header of headers) {
      let emailCount = 0
      let roleCount = 0
      let totalNonEmpty = 0
      
      // Sample first 10 rows to determine column content type
      const sampleSize = Math.min(10, data.length)
      
      for (let i = 0; i < sampleSize; i++) {
        const value = data[i][header]?.toString()?.trim()
        if (!value) continue
        
        totalNonEmpty++
        
        // Check if value looks like an email
        if (value.includes('@') && value.includes('.')) {
          const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
          if (emailRegex.test(value)) {
            emailCount++
          }
        }
        
        // Check if value looks like a role (case-insensitive)
        const lowerValue = value.toLowerCase()
        const roleKeywords = [
          'user', 'admin', 'administrator', 'manager', 'employee', 
          'staff', 'member', 'owner', 'editor', 'viewer', 'guest'
        ]
        if (roleKeywords.includes(lowerValue)) {
          roleCount++
        }
      }
      
      // If more than 70% of non-empty values in this column are emails, it's the email column
      if (totalNonEmpty > 0 && (emailCount / totalNonEmpty) > 0.7) {
        emailField = header
      }
      
      // If more than 50% of non-empty values look like roles, it's the role column
      if (totalNonEmpty > 0 && (roleCount / totalNonEmpty) > 0.5) {
        roleField = header
      }
    }
    
    console.log(`📧 Email column detected: ${emailField || 'None found'}`)
    console.log(`👤 Role column detected: ${roleField || 'None found'}`)
    
    return { emailField, roleField }
  }

  const validateParsedData = (data: any[]): { valid: any[], invalid: any[], errors: string[] } => {
    const valid: any[] = []
    const invalid: any[] = []
    const errors: string[] = []
    
    if (data.length === 0) {
      errors.push("File is empty or contains no valid data")
      return { valid, invalid, errors }
    }
    
    // Detect email and role columns by analyzing data content
    const { emailField, roleField } = detectEmailAndRoleColumns(data)
    setDetectedColumns({ emailField, roleField })
    
    if (!emailField) {
      const headers = Object.keys(data[0])
      errors.push(`No email column detected. Please ensure one column contains valid email addresses with @ symbols. Available columns: ${headers.join(', ')}`)
      return { valid, invalid, errors }
    }
    
    console.log(`📧 Detected email column: "${emailField}"`)
    if (roleField) {
      console.log(`👤 Detected role column: "${roleField}"`)
    } else {
      console.log(`👤 No role column detected, will default to "user"`)
    }
    
    data.forEach((row, index) => {
      const rowNumber = index + 1
      const email = row[emailField]?.toString()?.trim()
      const role = roleField ? row[roleField]?.toString()?.trim() : 'user'
      
      if (!email) {
        invalid.push({ 
          ...row, 
          rowNumber, 
          error: `Missing email address in column "${emailField}"` 
        })
        return
      }
      
      const emailError = validateEmail(email)
      if (emailError) {
        invalid.push({ 
          ...row, 
          rowNumber, 
          error: `Invalid email "${email}": ${emailError}` 
        })
        return
      }
      
      // Normalize and validate role (very flexible mapping)
      const normalizedRole = normalizeRole(role || 'user')
      
      if (!normalizedRole) {
        invalid.push({ 
          ...row, 
          rowNumber, 
          error: `Invalid role "${role}". Valid options: user, admin, manager, administrator, employee, staff, etc.` 
        })
        return
      }
      
      valid.push({
        email: email.toLowerCase(),
        role: normalizedRole,
        rowNumber,
        originalRow: row
      })
    })
    
    // Check for duplicate emails
    const emailSet = new Set()
    const duplicates: string[] = []
    
    // Process in reverse to keep the first occurrence
    for (let i = valid.length - 1; i >= 0; i--) {
      const row = valid[i]
      if (emailSet.has(row.email)) {
        duplicates.push(row.email)
        invalid.push(valid.splice(i, 1)[0])
      } else {
        emailSet.add(row.email)
      }
    }
    
    if (duplicates.length > 0) {
      errors.push(`Duplicate emails found (keeping first occurrence): ${[...new Set(duplicates)].join(', ')}`)
    }
    
    return { valid, invalid, errors }
  }

  // Clear errors when user starts typing
  const handleEmailChange = (email: string) => {
    setInviteEmail(email)
    if (errors.email) {
      setErrors(prev => ({ ...prev, email: "" }))
    }
    if (generatedLink) {
      setGeneratedLink("")
    }
  }

  // Single invitation handler
  const handleSendInvitation = async () => {
    setErrors({})
    
    const emailError = validateEmail(inviteEmail)
    if (emailError) {
      setErrors({ email: emailError })
      addNotification(emailError, "error")
      return
    }

    try {
      setLoading(true)
      const response = await apiCall("/auth/generate-signup-link", {
        email: inviteEmail.trim().toLowerCase(),
        role: inviteRole,
      })

      if (response.status === "SUCCESS") {
        const signupLink = response.data.signup_url || response.data.signup_link
        setGeneratedLink(signupLink)
        addNotification(`✅ Invitation sent successfully to ${inviteEmail}!`, "success")
        setInviteEmail("")
        setErrors({})
      } else {
        addNotification(response.message || "Failed to create invitation", "error")
      }
    } catch (error: any) {
      console.error("Error creating invitation:", error)
      addNotification(error.message, "error")
      
      if (error.message.includes("email")) {
        setErrors({ email: error.message })
      }
    } finally {
      setLoading(false)
    }
  }

  // File validation - CSV ONLY
  const validateFile = (file: File): string | null => {
    const allowedExtensions = ['.csv']
    const fileExtension = file.name.toLowerCase().substring(file.name.lastIndexOf('.'))
    
    if (!allowedExtensions.includes(fileExtension)) {
      return "Only CSV files are supported. Please convert Excel files to CSV format using 'Save As' → 'CSV (Comma delimited)'"
    }
    
    if (file.size > 5 * 1024 * 1024) { // 5MB limit
      return "File size must be less than 5MB"
    }
    
    return null
  }

  // File parsing - CSV ONLY
  const parseFile = async (file: File): Promise<any[]> => {
    return new Promise((resolve, reject) => {
      // Parse CSV with Papa Parse
      Papa.parse(file, {
        header: true,
        skipEmptyLines: true,
        comments: '#',
        transformHeader: (header) => header.trim(),
        transform: (value) => value.trim(),
        complete: (results) => {
          if (results.errors.length > 0) {
            const criticalErrors = results.errors.filter(err => err.type === 'Delimiter' || err.type === 'Quotes')
            if (criticalErrors.length > 0) {
              reject(new Error(`CSV parsing error: ${criticalErrors[0].message}`))
              return
            }
          }
          resolve(results.data)
        },
        error: (error) => {
          reject(new Error(`Failed to parse CSV: ${error.message}`))
        }
      })
    })
  }

  // Handle file selection
  const handleFileSelect = async (file: File) => {
    const fileError = validateFile(file)
    if (fileError) {
      addNotification(fileError, "error")
      return
    }

    setBulkFile(file)
    setBulkResults(null)
    setParsedData([])
    setDetectedColumns({ emailField: null, roleField: null })

    try {
      addNotification("📁 Parsing CSV file...", "success")
      const parsed = await parseFile(file)
      
      const { valid, invalid, errors } = validateParsedData(parsed)
      
      if (errors.length > 0) {
        addNotification(`❌ File validation errors:\n${errors.join('\n')}`, "error")
        return
      }
      
      setParsedData(valid)
      
      if (invalid.length > 0) {
        addNotification(`⚠️ Found ${invalid.length} invalid rows that will be skipped. Check console for details.`, "error")
        console.log('Invalid rows:', invalid)
      }
      
      addNotification(`✅ CSV parsed successfully! Found ${valid.length} valid invitations`, "success")
    } catch (error: any) {
      addNotification(`❌ Error parsing CSV: ${error.message}`, "error")
      setBulkFile(null)
      setDetectedColumns({ emailField: null, roleField: null })
    }
  }

  // File drag and drop handlers
  const handleFileDrop = (e: React.DragEvent) => {
    e.preventDefault()
    setDragActive(false)
    
    const files = Array.from(e.dataTransfer.files)
    if (files.length > 0) {
      handleFileSelect(files[0])
    }
  }

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = Array.from(e.target.files || [])
    if (files.length > 0) {
      handleFileSelect(files[0])
    }
  }

  // FIXED: Bulk upload handler using existing apiCall
  const handleBulkUpload = async () => {
    if (!bulkFile || parsedData.length === 0) {
      addNotification("Please select and validate a file first", "error")
      return
    }

    try {
      setBulkLoading(true)
      setUploadProgress(0)
      
      // Create FormData
      const formData = new FormData()
      formData.append('file', bulkFile)
      
      const progressInterval = setInterval(() => {
        setUploadProgress(prev => Math.min(prev + 10, 90))
      }, 100)

      // Use existing apiCall but pass FormData directly
      const response = await apiCall("/auth/bulk-invite", formData, "POST")
      
      clearInterval(progressInterval)
      setUploadProgress(100)

      if (response.status === "SUCCESS") {
        setBulkResults(response.data)
        addNotification(`✅ Bulk upload completed! ${response.data.successful}/${response.data.total_processed} invitations sent successfully`, "success")
      } else {
        addNotification(response.message || "Bulk upload failed", "error")
      }
    } catch (error: any) {
      console.error("Error with bulk upload:", error)
      addNotification(`❌ Bulk upload error: ${error.message}`, "error")
    } finally {
      setBulkLoading(false)
      setUploadProgress(0)
    }
  }

  // Template download
  const downloadTemplate = () => {
    const csvContent = `Name,Email,Department,Role
John Doe,john.doe@company.com,Engineering,user
Jane Smith,jane.smith@company.com,HR,ADMIN
Mike Johnson,mike.j@company.com,Marketing,User
Sarah Wilson,sarah.wilson@company.com,IT,Administrator
Bob Brown,bob.brown@company.com,Finance,Manager
Alice Green,alice.g@company.com,Support,employee

# Role examples that work (case-insensitive):
# USER, User, user → becomes "user"
# ADMIN, Admin, admin, Administrator, Manager, Supervisor → becomes "admin"
# employee, staff, member, contributor → becomes "user"
# Any unrecognized role → defaults to "user"

# Notes:
# - CSV format only (convert Excel files to CSV first)
# - Any column containing valid email addresses (with @ symbol) will be detected automatically
# - Role detection works with any case: USER, User, user, ADMIN, Admin, admin, etc.
# - Column names don't matter - the system detects content automatically
# - Lines starting with # are comments and will be ignored`
    
    const blob = new Blob([csvContent], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = 'bulk-invite-template.csv'
    link.click()
    URL.revokeObjectURL(url)
    addNotification("📋 CSV template downloaded!", "success")
  }

  // Copy to clipboard
  const copyToClipboard = async () => {
    try {
      await navigator.clipboard.writeText(generatedLink)
      addNotification("✅ Invitation link copied to clipboard!", "success")
    } catch (error) {
      const textArea = document.createElement("textarea")
      textArea.value = generatedLink
      document.body.appendChild(textArea)
      textArea.select()
      document.execCommand('copy')
      document.body.removeChild(textArea)
      addNotification("✅ Invitation link copied to clipboard!", "success")
    }
  }

  // Reset bulk upload state
  const resetBulkUpload = () => {
    setBulkFile(null)
    setBulkResults(null)
    setParsedData([])
    setDetectedColumns({ emailField: null, roleField: null })
    setUploadProgress(0)
    if (fileInputRef.current) {
      fileInputRef.current.value = ''
    }
  }

  const isFormValid = () => {
    return inviteEmail.trim() && !validateEmail(inviteEmail) && !loading
  }

  return (
    <div className="space-y-6">
      {/* Toggle between single and bulk invite */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
        <div className="flex items-center justify-between mb-6">
          <h3 className="text-xl font-semibold text-gray-900 flex items-center">
            <Mail className="w-6 h-6 mr-3 text-blue-600" />
            User Invitations
          </h3>
          
          <div className="flex items-center space-x-3">
            <span className={`text-sm ${!showBulkUpload ? 'text-blue-600 font-medium' : 'text-gray-500'}`}>
              Single Invite
            </span>
            <button
              onClick={() => {
                setShowBulkUpload(!showBulkUpload)
                resetBulkUpload()
              }}
              className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                showBulkUpload ? 'bg-blue-600' : 'bg-gray-300'
              }`}
            >
              <span
                className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                  showBulkUpload ? 'translate-x-6' : 'translate-x-1'
                }`}
              />
            </button>
            <span className={`text-sm ${showBulkUpload ? 'text-blue-600 font-medium' : 'text-gray-500'}`}>
              Bulk Upload
            </span>
          </div>
        </div>

        {!showBulkUpload ? (
          // Single invitation form
          <div className="space-y-6">
            <p className="text-gray-600">Create signup tokens and invite new users to the QTEAM system</p>
            
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Email Address *
              </label>
              <input
                type="email"
                value={inviteEmail}
                onChange={(e) => handleEmailChange(e.target.value)}
                placeholder="Enter user's email address"
                className={`w-full px-4 py-3 border rounded-lg focus:ring-2 focus:border-blue-500 transition-colors ${
                  errors.email 
                    ? 'border-red-300 focus:ring-red-500 focus:border-red-500' 
                    : generatedLink 
                      ? 'border-green-300 bg-green-50 focus:ring-green-500' 
                      : 'border-gray-300 focus:ring-blue-500'
                }`}
                required
                disabled={loading}
                autoComplete="email"
              />
              
              {errors.email && (
                <div className="mt-1 flex items-center text-red-600 text-sm">
                  <AlertCircle className="w-4 h-4 mr-1" />
                  {errors.email}
                </div>
              )}
              
              {!errors.email && inviteEmail && !validateEmail(inviteEmail) && (
                <div className="mt-1 flex items-center text-green-600 text-sm">
                  <CheckCircle className="w-4 h-4 mr-1" />
                  Email format is valid
                </div>
              )}
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">User Role</label>
              <select
                value={inviteRole}
                onChange={(e) => setInviteRole(e.target.value)}
                disabled={loading}
                className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 disabled:bg-gray-100 disabled:cursor-not-allowed"
              >
                <option value="user">User - Can request access</option>
                <option value="admin">Admin - Can approve requests and manage users</option>
              </select>
              <p className="text-xs text-gray-500 mt-1">
                Choose the appropriate role based on the user's responsibilities
              </p>
            </div>

            <button
              onClick={handleSendInvitation}
              disabled={!isFormValid()}
              className="bg-blue-600 text-white py-3 px-6 rounded-lg font-medium disabled:bg-gray-300 disabled:cursor-not-allowed hover:bg-blue-700 transition-all duration-200 flex items-center space-x-2 w-full sm:w-auto"
            >
              {loading ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  <span>Creating invitation...</span>
                </>
              ) : (
                <>
                  <UserPlus className="w-4 h-4" />
                  <span>Create Invitation</span>
                </>
              )}
            </button>

            {generatedLink && (
              <div className="mt-6 p-4 bg-green-50 rounded-lg border border-green-200 animate-in slide-in-from-top-2 duration-300">
                <h4 className="font-medium text-green-900 mb-2 flex items-center">
                  <CheckCircle className="w-5 h-5 mr-2" />
                  Invitation Created Successfully!
                </h4>
                <p className="text-sm text-green-700 mb-3">
                  📧 An invitation has been created for <strong>{inviteEmail}</strong> as a <strong>{inviteRole}</strong>. 
                  Share this secure link with them:
                </p>
                <div className="flex items-center space-x-2">
                  <input
                    type="text"
                    value={generatedLink}
                    readOnly
                    className="flex-1 px-3 py-2 text-sm border border-green-300 rounded bg-white font-mono text-xs"
                  />
                  <button
                    onClick={copyToClipboard}
                    className="px-3 py-2 bg-green-600 text-white rounded hover:bg-green-700 transition-colors flex items-center space-x-1 flex-shrink-0"
                    title="Copy invitation link"
                  >
                    <Copy className="w-4 h-4" />
                    <span className="text-sm hidden sm:inline">Copy</span>
                  </button>
                </div>
                <div className="mt-3 text-xs text-green-600 space-y-1">
                  <p>💡 Send this link via email or your preferred secure communication method</p>
                  <p>⏰ This invitation link will expire in 72 hours</p>
                  <p>🔒 The user will be able to create their account immediately using this link</p>
                </div>
              </div>
            )}
          </div>
        ) : (
          // Bulk upload form - CSV ONLY
          <div className="space-y-6">
            <div className="flex items-center justify-between">
              <p className="text-gray-600">Upload a CSV file to invite multiple users at once</p>
              <div className="flex items-center space-x-3">
                {bulkFile && (
                  <button
                    onClick={resetBulkUpload}
                    className="flex items-center space-x-2 text-gray-600 hover:text-gray-800 text-sm font-medium"
                  >
                    <X className="w-4 h-4" />
                    <span>Clear</span>
                  </button>
                )}
                <button
                  onClick={downloadTemplate}
                  className="flex items-center space-x-2 text-blue-600 hover:text-blue-800 text-sm font-medium"
                >
                  <Download className="w-4 h-4" />
                  <span>Download Template</span>
                </button>
              </div>
            </div>

            {/* CSV-Only Notice */}
            <div className="bg-blue-50 rounded-lg p-4 border border-blue-200">
              <h4 className="font-medium text-blue-900 mb-2">📋 Current Mode: CSV Only</h4>
              <p className="text-sm text-blue-800">
                Only CSV files are supported for bulk uploads. If you have an Excel file, please convert it to CSV format using "Save As" → "CSV (Comma delimited)" in Excel.
              </p>
            </div>

            {/* File upload area */}
            <div
              className={`border-2 border-dashed rounded-lg p-8 text-center transition-colors ${
                dragActive 
                  ? 'border-blue-400 bg-blue-50' 
                  : bulkFile 
                    ? 'border-green-400 bg-green-50' 
                    : 'border-gray-300 hover:border-gray-400'
              }`}
              onDragEnter={(e) => {
                e.preventDefault()
                setDragActive(true)
              }}
              onDragLeave={(e) => {
                e.preventDefault()
                setDragActive(false)
              }}
              onDragOver={(e) => e.preventDefault()}
              onDrop={handleFileDrop}
            >
              <input
                ref={fileInputRef}
                type="file"
                accept=".csv"
                onChange={handleFileChange}
                className="hidden"
              />
              
              <div className="space-y-4">
                <div className="flex justify-center">
                  {bulkFile ? (
                    <CheckCircle className="w-12 h-12 text-green-500" />
                  ) : (
                    <Upload className="w-12 h-12 text-gray-400" />
                  )}
                </div>
                
                {bulkFile ? (
                  <div>
                    <p className="text-lg font-medium text-green-900">CSV File Selected</p>
                    <p className="text-sm text-green-700">{bulkFile.name}</p>
                    <p className="text-xs text-green-600 mt-1">
                      {parsedData.length} valid invitations ready to process
                    </p>
                  </div>
                ) : (
                  <div>
                    <p className="text-lg font-medium text-gray-900">
                      Drag and drop your CSV file here, or click to browse
                    </p>
                    <p className="text-sm text-gray-500">
                      Supports CSV files (.csv) up to 5MB
                    </p>
                  </div>
                )}
                
                <button
                  onClick={() => fileInputRef.current?.click()}
                  className="bg-blue-600 text-white px-6 py-2 rounded-lg hover:bg-blue-700 transition-colors font-medium"
                >
                  {bulkFile ? 'Choose Different File' : 'Choose CSV File'}
                </button>
              </div>
            </div>

            {/* Show when no emails detected */}
            {bulkFile && parsedData.length === 0 && !detectedColumns.emailField && (
              <div className="bg-red-50 rounded-lg p-4 border border-red-200">
                <h4 className="font-medium text-red-900 mb-2">❌ No Email Addresses Found</h4>
                <div className="text-sm text-red-800 space-y-2">
                  <p>The system couldn't find any valid email addresses in your CSV file.</p>
                  <p><strong>Please ensure:</strong></p>
                  <div className="ml-4 space-y-1">
                    <p>• At least one column contains email addresses with @ symbols</p>
                    <p>• Email addresses are properly formatted (e.g., user@company.com)</p>
                    <p>• The file isn't empty or contains actual data beyond headers</p>
                    <p>• The file is in CSV format (not Excel)</p>
                  </div>
                  <div className="mt-3 p-2 bg-white rounded border">
                    <p className="text-xs text-gray-700 font-medium mb-1">Example of what we're looking for:</p>
                    <div className="font-mono text-xs text-gray-600">
                      john.doe@company.com ✓<br/>
                      jane@example.org ✓<br/>
                      invalid-email ✗<br/>
                      @missing-user.com ✗
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* Show detected columns */}
            {bulkFile && parsedData.length > 0 && detectedColumns.emailField && (
              <div className="bg-green-50 rounded-lg p-4 border border-green-200">
                <h4 className="font-medium text-green-900 mb-2">🎯 Auto-Detection Results</h4>
                <div className="text-sm text-green-800 space-y-1">
                  <p>📧 <strong>Email column found:</strong> "{detectedColumns.emailField}" - Contains valid email addresses</p>
                  <p>👤 <strong>Role column:</strong> {detectedColumns.roleField ? `"${detectedColumns.roleField}" - Contains user roles` : 'Not detected - All users will be assigned "user" role'}</p>
                  <p className="text-green-600 text-xs mt-2 flex items-center">
                    <CheckCircle className="w-3 h-3 mr-1" />
                    Ready to process {parsedData.length} invitations
                  </p>
                </div>
              </div>
            )}

            {/* File format requirements */}
            <div className="bg-blue-50 rounded-lg p-4 border border-blue-200">
              <h4 className="font-medium text-blue-900 mb-2">📋 How It Works - Automatic Detection</h4>
              <div className="text-sm text-blue-800 space-y-2">
                <div>
                  <p><strong>📧 Email Detection:</strong></p>
                  <p className="ml-4 text-blue-700">• System automatically finds columns containing valid email addresses (with @ symbol)</p>
                  <p className="ml-4 text-blue-700">• Column names don't matter - just put emails anywhere in your CSV</p>
                </div>
                <div>
                  <p><strong>👤 Role Detection (Optional):</strong></p>
                  <p className="ml-4 text-blue-700">• Automatically detects columns with role values (case-insensitive)</p>
                  <p className="ml-4 text-blue-700">• <strong>Admin roles:</strong> admin, ADMIN, Administrator, Manager, Supervisor, etc.</p>
                  <p className="ml-4 text-blue-700">• <strong>User roles:</strong> user, USER, Employee, Staff, Member, etc.</p>
                  <p className="ml-4 text-blue-700">• If no role column found, everyone defaults to "user"</p>
                </div>
                <div className="mt-3">
                  <p><strong>✨ Example CSV format:</strong></p>
                  <div className="p-2 bg-white rounded border mt-2">
                    <div className="font-mono text-xs text-gray-700">
                      Name,Email,Role<br/>
                      John Doe,john@company.com,user<br/>
                      Jane Smith,jane@company.com,admin<br/>
                      Mike Johnson,mike@company.com,manager
                    </div>
                  </div>
                  <p className="text-blue-600 text-xs mt-2">
                    💡 <strong>Pro tip:</strong> Just make sure your CSV has email addresses with @ symbols - we'll find them automatically!
                  </p>
                </div>
              </div>
            </div>

            {/* Preview data */}
            {parsedData.length > 0 && (
              <div className="bg-white border border-gray-200 rounded-lg">
                <div className="px-4 py-3 border-b border-gray-200">
                  <h4 className="font-medium text-gray-900">Preview ({parsedData.length} invitations)</h4>
                </div>
                <div className="max-h-64 overflow-y-auto">
                  <table className="w-full text-sm">
                    <thead className="bg-gray-50">
                      <tr>
                        <th className="px-4 py-2 text-left font-medium text-gray-900">Email</th>
                        <th className="px-4 py-2 text-left font-medium text-gray-900">Role</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-200">
                      {parsedData.slice(0, 10).map((row, index) => (
                        <tr key={index}>
                          <td className="px-4 py-2 text-gray-900">{row.email}</td>
                          <td className="px-4 py-2">
                            <span className={`px-2 py-1 rounded-full text-xs font-medium ${
                              row.role === 'admin' 
                                ? 'bg-purple-100 text-purple-800' 
                                : 'bg-blue-100 text-blue-800'
                            }`}>
                              {row.role}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  {parsedData.length > 10 && (
                    <div className="px-4 py-2 text-sm text-gray-500 bg-gray-50">
                      ... and {parsedData.length - 10} more invitations
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Upload progress */}
            {bulkLoading && (
              <div className="bg-blue-50 rounded-lg p-4 border border-blue-200">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm font-medium text-blue-900">Processing invitations...</span>
                  <span className="text-sm text-blue-700">{uploadProgress}%</span>
                </div>
                <div className="w-full bg-blue-200 rounded-full h-2">
                  <div 
                    className="bg-blue-600 h-2 rounded-full transition-all duration-300"
                    style={{ width: `${uploadProgress}%` }}
                  ></div>
                </div>
              </div>
            )}

            {/* Upload button */}
            <button
              onClick={handleBulkUpload}
              disabled={!bulkFile || parsedData.length === 0 || bulkLoading}
              className="bg-green-600 text-white py-3 px-6 rounded-lg font-medium disabled:bg-gray-300 disabled:cursor-not-allowed hover:bg-green-700 transition-all duration-200 flex items-center space-x-2 w-full sm:w-auto"
            >
              {bulkLoading ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  <span>Processing {parsedData.length} invitations...</span>
                </>
              ) : (
                <>
                  <Users className="w-4 h-4" />
                  <span>Send {parsedData.length} Invitations</span>
                </>
              )}
            </button>

            {/* Results display */}
            {bulkResults && (
              <div className="bg-white border border-gray-200 rounded-lg">
                <div className="px-4 py-3 border-b border-gray-200">
                  <h4 className="font-medium text-gray-900 flex items-center">
                    <CheckCircle className="w-5 h-5 mr-2 text-green-500" />
                    Bulk Upload Results
                  </h4>
                </div>
                <div className="p-4 space-y-4">
                  {/* Summary */}
                  <div className="grid grid-cols-3 gap-4 text-center">
                    <div className="p-3 bg-green-50 rounded-lg">
                      <div className="text-2xl font-bold text-green-600">{bulkResults.successful}</div>
                      <div className="text-sm text-green-800">Successful</div>
                    </div>
                    <div className="p-3 bg-red-50 rounded-lg">
                      <div className="text-2xl font-bold text-red-600">{bulkResults.failed}</div>
                      <div className="text-sm text-red-800">Failed</div>
                    </div>
                    <div className="p-3 bg-blue-50 rounded-lg">
                      <div className="text-2xl font-bold text-blue-600">{bulkResults.total_processed}</div>
                      <div className="text-sm text-blue-800">Total Processed</div>
                    </div>
                  </div>

                  {/* Detailed results */}
                  {bulkResults.results && bulkResults.results.length > 0 && (
                    <div className="max-h-64 overflow-y-auto border border-gray-200 rounded-lg">
                      <table className="w-full text-sm">
                        <thead className="bg-gray-50">
                          <tr>
                            <th className="px-4 py-2 text-left font-medium text-gray-900">Email</th>
                            <th className="px-4 py-2 text-left font-medium text-gray-900">Status</th>
                            <th className="px-4 py-2 text-left font-medium text-gray-900">Details</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-gray-200">
                          {bulkResults.results.map((result: any, index: number) => (
                            <tr key={index}>
                              <td className="px-4 py-2 text-gray-900">{result.email}</td>
                              <td className="px-4 py-2">
                                <span className={`px-2 py-1 rounded-full text-xs font-medium ${
                                  result.status === 'SUCCESS' 
                                    ? 'bg-green-100 text-green-800' 
                                    : 'bg-red-100 text-red-800'
                                }`}>
                                  {result.status}
                                </span>
                              </td>
                              <td className="px-4 py-2 text-gray-600">
                                {result.status === 'SUCCESS' ? (
                                  <span className="text-green-600">✓ Invitation sent</span>
                                ) : (
                                  <span className="text-red-600">{result.error}</span>
                                )}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}

                  {/* Export results button */}
                  <button
                    onClick={() => {
                      const csvData = [
                        ['Email', 'Status', 'Role', 'Signup URL', 'Error'].join(','),
                        ...bulkResults.results.map((result: any) => [
                          `"${result.email}"`,
                          result.status,
                          `"${result.role || 'user'}"`,
                          `"${result.signup_url || ''}"`,
                          `"${result.error || ''}"`
                        ].join(','))
                      ].join('\n')

                      const blob = new Blob([csvData], { type: 'text/csv' })
                      const url = URL.createObjectURL(blob)
                      const link = document.createElement('a')
                      link.href = url
                      link.download = `bulk-invite-results-${new Date().toISOString().split('T')[0]}.csv`
                      link.click()
                      URL.revokeObjectURL(url)
                      addNotification("Results exported successfully!", "success")
                    }}
                    className="flex items-center space-x-2 text-blue-600 hover:text-blue-800 text-sm font-medium"
                  >
                    <Download className="w-4 h-4" />
                    <span>Export Results</span>
                  </button>
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* How it works section */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
        <h4 className="text-lg font-semibold text-gray-900 mb-4">
          {showBulkUpload ? "How CSV Bulk Upload Works" : "How User Invitations Work"}
        </h4>
        
        {showBulkUpload ? (
          <div className="space-y-3 text-sm text-gray-600">
            <div className="flex items-start space-x-3">
              <div className="w-6 h-6 bg-blue-100 rounded-full flex items-center justify-center flex-shrink-0 mt-0.5">
                <span className="text-blue-600 font-semibold text-xs">1</span>
              </div>
              <div>
                <strong>Prepare CSV File:</strong> Create a CSV file with email addresses and optionally roles. Download our template to get started.
              </div>
            </div>
            <div className="flex items-start space-x-3">
              <div className="w-6 h-6 bg-blue-100 rounded-full flex items-center justify-center flex-shrink-0 mt-0.5">
                <span className="text-blue-600 font-semibold text-xs">2</span>
              </div>
              <div>
                <strong>Upload & Auto-Detect:</strong> Drag and drop your CSV file. The system automatically finds email columns and role columns regardless of naming.
              </div>
            </div>
            <div className="flex items-start space-x-3">
              <div className="w-6 h-6 bg-blue-100 rounded-full flex items-center justify-center flex-shrink-0 mt-0.5">
                <span className="text-blue-600 font-semibold text-xs">3</span>
              </div>
              <div>
                <strong>Process Invitations:</strong> Review the preview and click "Send Invitations" to process all valid entries at once.
              </div>
            </div>
            <div className="flex items-start space-x-3">
              <div className="w-6 h-6 bg-green-100 rounded-full flex items-center justify-center flex-shrink-0 mt-0.5">
                <CheckCircle className="w-3 h-3 text-green-600" />
              </div>
              <div>
                <strong>Review Results:</strong> See a detailed report of successful and failed invitations, and export the results for your records.
              </div>
            </div>
            <div className="mt-4 p-3 bg-blue-50 rounded-lg">
              <p className="text-blue-800 text-sm">
                <strong>💡 Note:</strong> Excel files are not supported. Please convert Excel files to CSV format using "Save As" → "CSV (Comma delimited)" in Excel.
              </p>
            </div>
          </div>
        ) : (
          <div className="space-y-3 text-sm text-gray-600">
            <div className="flex items-start space-x-3">
              <div className="w-6 h-6 bg-blue-100 rounded-full flex items-center justify-center flex-shrink-0 mt-0.5">
                <span className="text-blue-600 font-semibold text-xs">1</span>
              </div>
              <div>
                <strong>Create Invitation:</strong> Enter the user's email and select their role to generate a secure signup token.
              </div>
            </div>
            <div className="flex items-start space-x-3">
              <div className="w-6 h-6 bg-blue-100 rounded-full flex items-center justify-center flex-shrink-0 mt-0.5">
                <span className="text-blue-600 font-semibold text-xs">2</span>
              </div>
              <div>
                <strong>Share Link:</strong> Send the generated invitation link to the user via email or secure communication.
              </div>
            </div>
            <div className="flex items-start space-x-3">
              <div className="w-6 h-6 bg-blue-100 rounded-full flex items-center justify-center flex-shrink-0 mt-0.5">
                <span className="text-blue-600 font-semibold text-xs">3</span>
              </div>
              <div>
                <strong>User Registration:</strong> The user clicks the link and completes their account setup with their name and password.
              </div>
            </div>
            <div className="flex items-start space-x-3">
              <div className="w-6 h-6 bg-green-100 rounded-full flex items-center justify-center flex-shrink-0 mt-0.5">
                <CheckCircle className="w-3 h-3 text-green-600" />
              </div>
              <div>
                <strong>Account Active:</strong> The user can immediately log in and start using the QTEAM system.
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

// AWS Accounts Management Component
const AWSAccountsManagement: React.FC<{
  addNotification: (message: string, type: "success" | "error") => void
}> = ({ addNotification }) => {
  const [accounts, setAccounts] = useState<any[]>([])
  const [loading, setLoading] = useState(false)
  const [searchTerm, setSearchTerm] = useState("")
  const [filterActive, setFilterActive] = useState("all")
  const [showAddModal, setShowAddModal] = useState(false)
  const [showEditModal, setShowEditModal] = useState(false)
  const [editingAccount, setEditingAccount] = useState<any>(null)
  const [newAccount, setNewAccount] = useState({
    account_number: "",
    account_name: "",
  })

  // Pagination
  const [currentPage, setCurrentPage] = useState(1)
  const [itemsPerPage, setItemsPerPage] = useState(10)

  useEffect(() => {
    loadAccounts()
  }, [])

  const loadAccounts = async () => {
    try {
      setLoading(true)
      const response = await apiCall("/admin/aws-accounts", null, "GET")
      
      if (response.status === "SUCCESS" && response.data?.accounts) {
        setAccounts(response.data.accounts)
      } else {
        addNotification("Failed to load AWS accounts", "error")
      }
    } catch (err: any) {
      console.error("Error loading AWS accounts:", err)
      addNotification(`Error: ${err.message}`, "error")
    } finally {
      setLoading(false)
    }
  }

  const handleAddAccount = async () => {
    try {
      if (!newAccount.account_number.match(/^\d{12}$/)) {
        addNotification("Account number must be exactly 12 digits", "error")
        return
      }

      if (!newAccount.account_name.trim()) {
        addNotification("Account name is required", "error")
        return
      }

      setLoading(true)
      const response = await apiCall("/admin/aws-accounts", newAccount)
      
      if (response.status === "SUCCESS") {
        addNotification("AWS account added successfully!", "success")
        setNewAccount({ account_number: "", account_name: "" })
        setShowAddModal(false)
        await loadAccounts()
      } else {
        addNotification(response.message || "Failed to add account", "error")
      }
    } catch (error: any) {
      console.error("Error adding account:", error)
      addNotification(`Error: ${error.message}`, "error")
    } finally {
      setLoading(false)
    }
  }

  const handleEditAccount = async () => {
    try {
      if (!editingAccount?.account_name.trim()) {
        addNotification("Account name is required", "error")
        return
      }

      setLoading(true)
      const response = await apiCall(`/admin/aws-accounts/${editingAccount.account_id}`, {
        account_name: editingAccount.account_name,
        is_active: editingAccount.is_active
      }, "PUT")
      
      if (response.status === "SUCCESS") {
        addNotification("AWS account updated successfully!", "success")
        setShowEditModal(false)
        setEditingAccount(null)
        await loadAccounts()
      } else {
        addNotification(response.message || "Failed to update account", "error")
      }
    } catch (error: any) {
      console.error("Error updating account:", error)
      addNotification(`Error: ${error.message}`, "error")
    } finally {
      setLoading(false)
    }
  }

  const handleDeactivateAccount = async (accountId: string, accountName: string) => {
    if (!confirm(`Are you sure you want to deactivate "${accountName}"? This will prevent new requests but won't affect active sessions.`)) {
      return
    }

    try {
      setLoading(true)
      const response = await apiCall(`/admin/aws-accounts/${accountId}`, null, "DELETE")
      
      if (response.status === "SUCCESS") {
        addNotification("AWS account deactivated successfully!", "success")
        await loadAccounts()
      } else {
        addNotification(response.message || "Failed to deactivate account", "error")
      }
    } catch (error: any) {
      console.error("Error deactivating account:", error)
      addNotification(`Error: ${error.message}`, "error")
    } finally {
      setLoading(false)
    }
  }

  const exportAccounts = () => {
    const csvData = [
      ['Account Name', 'Account Number', 'Status', 'Created At', 'Created By'].join(','),
      ...filteredAccounts.map(account => [
        `"${account.account_name}"`,
        account.account_number,
        account.is_active ? 'Active' : 'Inactive',
        new Date(account.created_at).toLocaleDateString(),
        `"${account.created_by}"`
      ].join(','))
    ].join('\n')

    const blob = new Blob([csvData], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = `aws-accounts-${new Date().toISOString().split('T')[0]}.csv`
    link.click()
    URL.revokeObjectURL(url)
    
    addNotification("AWS accounts exported successfully!", "success")
  }

  // Filter accounts
  const filteredAccounts = accounts.filter(account => {
    const matchesSearch = 
      account.account_name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      account.account_number.includes(searchTerm) ||
      account.created_by?.toLowerCase().includes(searchTerm.toLowerCase())
    
    const matchesFilter = 
      filterActive === "all" || 
      (filterActive === "active" && account.is_active) || 
      (filterActive === "inactive" && !account.is_active)
    
    return matchesSearch && matchesFilter
  })

  // Pagination
  const totalItems = filteredAccounts.length
  const totalPages = Math.ceil(totalItems / itemsPerPage)
  const startIndex = (currentPage - 1) * itemsPerPage
  const endIndex = startIndex + itemsPerPage
  const paginatedAccounts = filteredAccounts.slice(startIndex, endIndex)

  // Reset page when filters change
  useEffect(() => {
    setCurrentPage(1)
  }, [searchTerm, filterActive])

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h3 className="text-xl font-semibold text-gray-900 flex items-center">
            <Cloud className="w-6 h-6 mr-3 text-orange-500" />
            AWS Accounts Management
          </h3>
          <p className="text-gray-600 mt-1">Manage available AWS accounts for temporary access requests</p>
        </div>
        <div className="flex items-center space-x-3">
          <button
            onClick={exportAccounts}
            disabled={accounts.length === 0}
            className="flex items-center space-x-2 px-4 py-2 text-green-600 border border-green-300 rounded-lg hover:bg-green-50 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <Download className="w-4 h-4" />
            <span>Export CSV</span>
          </button>
          <button
            onClick={() => setShowAddModal(true)}
            className="flex items-center space-x-2 bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition-colors"
          >
            <Plus className="w-4 h-4" />
            <span>Add Account</span>
          </button>
        </div>
      </div>

      {/* Filters and Search */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
          <div className="flex items-center space-x-4">
            <div className="relative">
              <Search className="w-4 h-4 absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400" />
              <input
                type="text"
                placeholder="Search accounts..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="pl-10 pr-4 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 w-64"
              />
            </div>
            <select
              value={filterActive}
              onChange={(e) => setFilterActive(e.target.value)}
              className="px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            >
              <option value="all">All Accounts</option>
              <option value="active">Active Only</option>
              <option value="inactive">Inactive Only</option>
            </select>
          </div>
          <div className="flex items-center space-x-3">
            <select
              value={itemsPerPage}
              onChange={(e) => {
                setItemsPerPage(Number(e.target.value))
                setCurrentPage(1)
              }}
              className="px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            >
              <option value={5}>5 per page</option>
              <option value={10}>10 per page</option>
              <option value={25}>25 per page</option>
              <option value={50}>50 per page</option>
            </select>
            <button
              onClick={loadAccounts}
              disabled={loading}
              className="text-blue-600 hover:text-blue-800 flex items-center text-sm font-medium px-3 py-2 rounded-lg hover:bg-blue-50 transition-colors disabled:opacity-50"
            >
              <RefreshCw className={`w-4 h-4 mr-1 ${loading ? "animate-spin" : ""}`} />
              Refresh
            </button>
          </div>
        </div>

        {/* Summary Stats */}
        <div className="mt-4 pt-4 border-t border-gray-200">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
            <div className="text-center p-3 bg-orange-50 rounded-lg">
              <div className="text-xl font-bold text-orange-600">{accounts.length}</div>
              <div className="text-gray-600">Total AWS Accounts</div>
            </div>
            <div className="text-center p-3 bg-green-50 rounded-lg">
              <div className="text-xl font-bold text-green-600">
                {accounts.filter(a => a.is_active).length}
              </div>
              <div className="text-gray-600">Active</div>
            </div>
            <div className="text-center p-3 bg-red-50 rounded-lg">
              <div className="text-xl font-bold text-red-600">
                {accounts.filter(a => !a.is_active).length}
              </div>
              <div className="text-gray-600">Inactive</div>
            </div>
            <div className="text-center p-3 bg-gray-50 rounded-lg">
              <div className="text-xl font-bold text-gray-600">{filteredAccounts.length}</div>
              <div className="text-gray-600">Filtered Results</div>
            </div>
          </div>
        </div>
      </div>

      {/* Accounts Table */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
        {paginatedAccounts.length === 0 ? (
          <div className="p-12 text-center">
            <div className="w-16 h-16 bg-orange-100 rounded-full flex items-center justify-center mx-auto mb-4">
              <Cloud className="w-8 h-8 text-orange-500" />
            </div>
            <div className="text-gray-500 text-lg mb-2">
              {searchTerm || filterActive !== "all" ? "No accounts found" : "No AWS accounts configured"}
            </div>
            <div className="text-gray-400 text-sm">
              {searchTerm || filterActive !== "all" 
                ? "Try adjusting your search or filters" 
                : "Add your first AWS account to get started"}
            </div>
          </div>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead className="bg-gray-50 border-b border-gray-200">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Account Details
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Status
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Created
                    </th>
                    <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Actions
                    </th>
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-200">
                  {paginatedAccounts.map((account) => (
                    <tr key={account.account_id} className="hover:bg-gray-50">
                      <td className="px-6 py-4">
                        <div>
                          <div className="text-sm font-medium text-gray-900">{account.account_name}</div>
                          <div className="text-sm text-gray-500">{account.account_number}</div>
                        </div>
                      </td>
                      <td className="px-6 py-4">
                        <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${
                          account.is_active 
                            ? 'bg-green-100 text-green-800' 
                            : 'bg-red-100 text-red-800'
                        }`}>
                          {account.is_active ? 'Active' : 'Inactive'}
                        </span>
                      </td>
                      <td className="px-6 py-4 text-sm text-gray-500">
                        <div>{new Date(account.created_at).toLocaleDateString()}</div>
                        <div className="text-xs">by {account.created_by}</div>
                      </td>
                      <td className="px-6 py-4 text-right text-sm font-medium space-x-2">
                        <button
                          onClick={() => {
                            setEditingAccount({ ...account })
                            setShowEditModal(true)
                          }}
                          className="text-blue-600 hover:text-blue-900 transition-colors"
                        >
                          Edit
                        </button>
                        {account.is_active && (
                          <button
                            onClick={() => handleDeactivateAccount(account.account_id, account.account_name)}
                            className="text-red-600 hover:text-red-900 transition-colors"
                          >
                            Deactivate
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Pagination */}
            {totalPages > 1 && (
              <div className="bg-gray-50 px-6 py-3 border-t border-gray-200">
                <div className="flex items-center justify-between">
                  <div className="text-sm text-gray-700">
                    Showing {startIndex + 1} to {Math.min(endIndex, totalItems)} of {totalItems} accounts
                  </div>
                  <div className="flex items-center space-x-2">
                    <button
                      onClick={() => setCurrentPage(currentPage - 1)}
                      disabled={currentPage === 1}
                      className="px-3 py-1 text-sm border border-gray-300 rounded hover:bg-gray-100 disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                      Previous
                    </button>
                    <span className="text-sm text-gray-600">
                      Page {currentPage} of {totalPages}
                    </span>
                    <button
                      onClick={() => setCurrentPage(currentPage + 1)}
                      disabled={currentPage === totalPages}
                      className="px-3 py-1 text-sm border border-gray-300 rounded hover:bg-gray-100 disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                      Next
                    </button>
                  </div>
                </div>
              </div>
            )}
          </>
        )}
      </div>

      {/* Add Account Modal */}
      {showAddModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-xl p-6 max-w-md w-full mx-4">
            <h3 className="text-lg font-semibold text-gray-900 mb-4">Add New AWS Account</h3>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Account Number *
                </label>
                <input
                  type="text"
                  value={newAccount.account_number}
                  onChange={(e) => setNewAccount(prev => ({ ...prev, account_number: e.target.value.replace(/\D/g, '').slice(0, 12) }))}
                  placeholder="123456789012"
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                  maxLength={12}
                />
                <p className="text-xs text-gray-500 mt-1">Must be exactly 12 digits</p>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Account Name *
                </label>
                <input
                  type="text"
                  value={newAccount.account_name}
                  onChange={(e) => setNewAccount(prev => ({ ...prev, account_name: e.target.value }))}
                  placeholder="Production, Development, Testing, etc."
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                />
              </div>
            </div>
            <div className="flex items-center justify-end space-x-3 mt-6">
              <button
                onClick={() => {
                  setShowAddModal(false)
                  setNewAccount({ account_number: "", account_name: "" })
                }}
                className="px-4 py-2 text-gray-600 hover:text-gray-800 transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleAddAccount}
                disabled={loading || !newAccount.account_number || !newAccount.account_name}
                className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {loading ? "Adding..." : "Add Account"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Edit Account Modal */}
      {showEditModal && editingAccount && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-xl p-6 max-w-md w-full mx-4">
            <h3 className="text-lg font-semibold text-gray-900 mb-4">Edit AWS Account</h3>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Account Number
                </label>
                <input
                  type="text"
                  value={editingAccount.account_number}
                  readOnly
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg bg-gray-100 text-gray-600"
                />
                <p className="text-xs text-gray-500 mt-1">Account number cannot be changed</p>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Account Name *
                </label>
                <input
                  type="text"
                  value={editingAccount.account_name}
                  onChange={(e) => setEditingAccount(prev => ({ ...prev, account_name: e.target.value }))}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                />
              </div>
              <div>
                <label className="flex items-center">
                  <input
                    type="checkbox"
                    checked={editingAccount.is_active}
                    onChange={(e) => setEditingAccount(prev => ({ ...prev, is_active: e.target.checked }))}
                    className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                  />
                  <span className="ml-2 text-sm text-gray-700">Account is active</span>
                </label>
                <p className="text-xs text-gray-500 mt-1">Inactive accounts cannot be selected for new requests</p>
              </div>
            </div>
            <div className="flex items-center justify-end space-x-3 mt-6">
              <button
                onClick={() => {
                  setShowEditModal(false)
                  setEditingAccount(null)
                }}
                className="px-4 py-2 text-gray-600 hover:text-gray-800 transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleEditAccount}
                disabled={loading || !editingAccount?.account_name}
                className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {loading ? "Saving..." : "Save Changes"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}


// Enhanced User Management Component
const UserManagement: React.FC<{
  addNotification: (message: string, type: "success" | "error") => void
}> = ({ addNotification }) => {
  const [users, setUsers] = useState<any[]>([])
  const [awsAccounts, setAwsAccounts] = useState<any[]>([])
  const [loading, setLoading] = useState(false)
  const [searchTerm, setSearchTerm] = useState("")
  const [filterRole, setFilterRole] = useState("all")
  const [filterStatus, setFilterStatus] = useState("all")
  const [filterAccount, setFilterAccount] = useState("all")
  const [showEditModal, setShowEditModal] = useState(false)
  const [editingUser, setEditingUser] = useState<any>(null)
  const [showDeleteModal, setShowDeleteModal] = useState(false)
  const [deletingUser, setDeletingUser] = useState<any>(null)
  const [actionLoading, setActionLoading] = useState<string | null>(null)
  
  // Pagination
  const [currentPage, setCurrentPage] = useState(1)
  const [itemsPerPage, setItemsPerPage] = useState(10)

  useEffect(() => {
    loadUsers()
    loadAwsAccounts()
  }, [])

  const loadUsers = async () => {
    try {
      setLoading(true)
      const response = await apiCall("/admin/users", null, "GET")
      
      if (response.status === "SUCCESS" && response.data?.users) {
        setUsers(response.data.users)
      } else {
        addNotification("Failed to load users", "error")
      }
    } catch (err: any) {
      console.error("Error loading users:", err)
      addNotification(`Error: ${err.message}`, "error")
    } finally {
      setLoading(false)
    }
  }

  const loadAwsAccounts = async () => {
    try {
      const response = await apiCall("/aws-accounts", null, "GET")
      if (response.status === "SUCCESS" && response.data?.accounts) {
        setAwsAccounts(response.data.accounts)
      }
    } catch (err: any) {
      console.error("Error loading AWS accounts:", err)
    }
  }

  const handleUserUpdate = async (userId: string, updates: any) => {
    try {
      setActionLoading(userId)
      const response = await apiCall(`/admin/users/${userId}`, updates, "PUT")
      
      if (response.status === "SUCCESS") {
        addNotification("User updated successfully!", "success")
        await loadUsers()
        setShowEditModal(false)
        setEditingUser(null)
      } else {
        addNotification(response.message || "Failed to update user", "error")
      }
    } catch (error: any) {
      console.error("Error updating user:", error)
      addNotification(`Error: ${error.message}`, "error")
    } finally {
      setActionLoading(null)
    }
  }

  const handleUserDelete = async (userId: string, force = false) => {
    try {
      setActionLoading(userId)
      const response = await apiCall(`/admin/users/${userId}?force=${force}`, null, "DELETE")
      
      if (response.status === "SUCCESS") {
        addNotification("User deleted successfully!", "success")
        await loadUsers()
        setShowDeleteModal(false)
        setDeletingUser(null)
      } else {
        addNotification(response.message || "Failed to delete user", "error")
      }
    } catch (error: any) {
      console.error("Error deleting user:", error)
      addNotification(`Error: ${error.message}`, "error")
    } finally {
      setActionLoading(null)
    }
  }

  const quickToggleStatus = async (user: any) => {
    const newStatus = !user.is_active
    await handleUserUpdate(user.user_id, { is_active: newStatus })
  }

  // Filter users
  const filteredUsers = users.filter((user) => {
    const matchesSearch = 
      user.full_name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      user.email.toLowerCase().includes(searchTerm.toLowerCase())
    
    const matchesRole = filterRole === "all" || user.role === filterRole
    const matchesStatus = 
      filterStatus === "all" || 
      (filterStatus === "active" && user.is_active) ||
      (filterStatus === "inactive" && !user.is_active)
    
    const matchesAccount = 
      filterAccount === "all" || 
      Object.keys(user.requests_by_account || {}).includes(filterAccount)
    
    return matchesSearch && matchesRole && matchesStatus && matchesAccount
  })

  // Pagination
  const totalItems = filteredUsers.length
  const totalPages = Math.ceil(totalItems / itemsPerPage)
  const startIndex = (currentPage - 1) * itemsPerPage
  const endIndex = startIndex + itemsPerPage
  const paginatedUsers = filteredUsers.slice(startIndex, endIndex)

  // Reset page when filters change
  useEffect(() => {
    setCurrentPage(1)
  }, [searchTerm, filterRole, filterStatus, filterAccount])

  const exportUsers = () => {
    const csvData = [
      ['Name', 'Email', 'Role', 'Status', 'Created', 'Last Login', 'Total Requests', 'Active Requests'].join(','),
      ...filteredUsers.map(user => [
        `"${user.full_name}"`,
        user.email,
        user.role,
        user.is_active ? 'Active' : 'Inactive',
        new Date(user.created_at).toLocaleDateString(),
        user.last_login ? new Date(user.last_login).toLocaleDateString() : 'Never',
        user.total_requests || 0,
        user.active_requests || 0
      ].join(','))
    ].join('\n')

    const blob = new Blob([csvData], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = `users-export-${new Date().toISOString().split('T')[0]}.csv`
    link.click()
    URL.revokeObjectURL(url)
    
    addNotification("Users exported successfully!", "success")
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h3 className="text-xl font-semibold text-gray-900 flex items-center">
            <Users className="w-6 h-6 mr-3 text-purple-600" />
            User Management
          </h3>
          <p className="text-gray-600 mt-1">Manage user accounts, permissions, and access by AWS account</p>
        </div>
        <div className="flex items-center space-x-3">
          <button
            onClick={exportUsers}
            disabled={filteredUsers.length === 0}
            className="flex items-center space-x-2 px-4 py-2 text-green-600 border border-green-300 rounded-lg hover:bg-green-50 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <Download className="w-4 h-4" />
            <span>Export CSV</span>
          </button>
          <button
            onClick={loadUsers}
            disabled={loading}
            className="text-purple-600 hover:text-purple-800 flex items-center text-sm font-medium px-3 py-2 rounded-lg hover:bg-purple-50 transition-colors disabled:opacity-50"
          >
            <RefreshCw className={`w-4 h-4 mr-1 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </button>
        </div>
      </div>

      {/* Filters and Search */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
          <div className="flex flex-wrap items-center gap-4">
            <div className="relative">
              <Search className="w-4 h-4 absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400" />
              <input
                type="text"
                placeholder="Search users..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="pl-10 pr-4 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-purple-500 focus:border-purple-500 w-64"
              />
            </div>
            
            <select
              value={filterRole}
              onChange={(e) => setFilterRole(e.target.value)}
              className="px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-purple-500 focus:border-purple-500"
            >
              <option value="all">All Roles</option>
              <option value="user">Users</option>
              <option value="admin">Admins</option>
            </select>

            <select
              value={filterStatus}
              onChange={(e) => setFilterStatus(e.target.value)}
              className="px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-purple-500 focus:border-purple-500"
            >
              <option value="all">All Status</option>
              <option value="active">Active</option>
              <option value="inactive">Inactive</option>
            </select>

            <select
              value={filterAccount}
              onChange={(e) => setFilterAccount(e.target.value)}
              className="px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-purple-500 focus:border-purple-500"
            >
              <option value="all">All AWS Accounts</option>
              {awsAccounts.map((account) => (
                <option key={account.account_id} value={account.account_name}>
                  {account.account_name}
                </option>
              ))}
            </select>
          </div>

          <div className="flex items-center space-x-3">
            <select
              value={itemsPerPage}
              onChange={(e) => {
                setItemsPerPage(Number(e.target.value))
                setCurrentPage(1)
              }}
              className="px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-purple-500 focus:border-purple-500"
            >
              <option value={5}>5 per page</option>
              <option value={10}>10 per page</option>
              <option value={25}>25 per page</option>
              <option value={50}>50 per page</option>
            </select>
          </div>
        </div>

        {/* Summary Stats */}
        <div className="mt-4 pt-4 border-t border-gray-200">
          <div className="grid grid-cols-2 md:grid-cols-5 gap-4 text-sm">
            <div className="text-center p-3 bg-purple-50 rounded-lg">
              <div className="text-xl font-bold text-purple-600">{users.length}</div>
              <div className="text-gray-600">Total Users</div>
            </div>
            <div className="text-center p-3 bg-green-50 rounded-lg">
              <div className="text-xl font-bold text-green-600">
                {users.filter(u => u.is_active).length}
              </div>
              <div className="text-gray-600">Active</div>
            </div>
            <div className="text-center p-3 bg-red-50 rounded-lg">
              <div className="text-xl font-bold text-red-600">
                {users.filter(u => !u.is_active).length}
              </div>
              <div className="text-gray-600">Inactive</div>
            </div>
            <div className="text-center p-3 bg-blue-50 rounded-lg">
              <div className="text-xl font-bold text-blue-600">
                {users.filter(u => u.role === 'admin').length}
              </div>
              <div className="text-gray-600">Admins</div>
            </div>
            <div className="text-center p-3 bg-gray-50 rounded-lg">
              <div className="text-xl font-bold text-gray-600">{filteredUsers.length}</div>
              <div className="text-gray-600">Filtered</div>
            </div>
          </div>
        </div>
      </div>

      {/* Users Table */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
        {paginatedUsers.length === 0 ? (
          <div className="p-12 text-center">
            <div className="w-16 h-16 bg-purple-100 rounded-full flex items-center justify-center mx-auto mb-4">
              <Users className="w-8 h-8 text-purple-500" />
            </div>
            <div className="text-gray-500 text-lg mb-2">
              {searchTerm || filterRole !== "all" || filterStatus !== "all" ? "No users found" : "No users configured"}
            </div>
            <div className="text-gray-400 text-sm">
              {searchTerm || filterRole !== "all" || filterStatus !== "all" 
                ? "Try adjusting your search or filters" 
                : "Users will appear here once they're invited"}
            </div>
          </div>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead className="bg-gray-50 border-b border-gray-200">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      User
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Role & Status
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Activity
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      AWS Account Access
                    </th>
                    <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Actions
                    </th>
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-200">
                  {paginatedUsers.map((user) => (
                    <tr key={user.user_id} className="hover:bg-gray-50">
                      <td className="px-6 py-4">
                        <div className="flex items-center">
                          <div className="flex-shrink-0 h-10 w-10">
                            <div className="h-10 w-10 rounded-full bg-purple-100 flex items-center justify-center">
                              <span className="text-sm font-medium text-purple-600">
                                {user.first_name?.[0]}{user.last_name?.[0]}
                              </span>
                            </div>
                          </div>
                          <div className="ml-4">
                            <div className="text-sm font-medium text-gray-900">{user.full_name}</div>
                            <div className="text-sm text-gray-500">{user.email}</div>
                          </div>
                        </div>
                      </td>
                      <td className="px-6 py-4">
                        <div className="space-y-1">
                          <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${
                            user.role === 'admin' 
                              ? 'bg-purple-100 text-purple-800' 
                              : 'bg-blue-100 text-blue-800'
                          }`}>
                            {user.role.toUpperCase()}
                          </span>
                          <div>
                            <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${
                              user.is_active 
                                ? 'bg-green-100 text-green-800' 
                                : 'bg-red-100 text-red-800'
                            }`}>
                              {user.is_active ? 'Active' : 'Inactive'}
                            </span>
                          </div>
                        </div>
                      </td>
                      <td className="px-6 py-4 text-sm text-gray-500">
                        <div className="space-y-1">
                          <div>Total Requests: <span className="font-medium">{user.total_requests || 0}</span></div>
                          <div>Active: <span className="font-medium text-green-600">{user.active_requests || 0}</span></div>
                          <div>Pending: <span className="font-medium text-yellow-600">{user.pending_requests || 0}</span></div>
                          <div className="text-xs">
                            Last Login: {user.last_login ? new Date(user.last_login).toLocaleDateString() : 'Never'}
                          </div>
                        </div>
                      </td>
                      <td className="px-6 py-4">
                        <div className="space-y-1">
                          {Object.keys(user.requests_by_account || {}).length > 0 ? (
                            Object.entries(user.requests_by_account).map(([accountName, stats]: [string, any]) => (
                              <div key={accountName} className="text-xs">
                                <div className="font-medium text-gray-900">{accountName}</div>
                                <div className="text-gray-500">
                                  {stats.total} total, {stats.active} active, {stats.pending} pending
                                </div>
                              </div>
                            ))
                          ) : (
                            <div className="text-xs text-gray-400">No requests yet</div>
                          )}
                        </div>
                      </td>
                      <td className="px-6 py-4 text-right text-sm font-medium space-x-2">
                        <button
                          onClick={() => quickToggleStatus(user)}
                          disabled={actionLoading === user.user_id}
                          className={`inline-flex items-center px-3 py-1 rounded-md text-sm font-medium transition-colors ${
                            user.is_active
                              ? 'text-red-600 bg-red-50 hover:bg-red-100'
                              : 'text-green-600 bg-green-50 hover:bg-green-100'
                          } disabled:opacity-50`}
                        >
                          {actionLoading === user.user_id ? (
                            <RefreshCw className="w-3 h-3 animate-spin" />
                          ) : user.is_active ? (
                            <>
                              <EyeOff className="w-3 h-3 mr-1" />
                              Deactivate
                            </>
                          ) : (
                            <>
                              <Eye className="w-3 h-3 mr-1" />
                              Activate
                            </>
                          )}
                        </button>
                        <button
                          onClick={() => {
                            setEditingUser(user)
                            setShowEditModal(true)
                          }}
                          className="text-blue-600 hover:text-blue-900 transition-colors px-3 py-1 rounded-md hover:bg-blue-50"
                        >
                          Edit
                        </button>
                        <button
                          onClick={() => {
                            setDeletingUser(user)
                            setShowDeleteModal(true)
                          }}
                          className="text-red-600 hover:text-red-900 transition-colors px-3 py-1 rounded-md hover:bg-red-50"
                        >
                          Delete
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Pagination */}
            {totalPages > 1 && (
              <div className="bg-gray-50 px-6 py-3 border-t border-gray-200">
                <div className="flex items-center justify-between">
                  <div className="text-sm text-gray-700">
                    Showing {startIndex + 1} to {Math.min(endIndex, totalItems)} of {totalItems} users
                  </div>
                  <div className="flex items-center space-x-2">
                    <button
                      onClick={() => setCurrentPage(currentPage - 1)}
                      disabled={currentPage === 1}
                      className="px-3 py-1 text-sm border border-gray-300 rounded hover:bg-gray-100 disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                      Previous
                    </button>
                    <span className="text-sm text-gray-600">
                      Page {currentPage} of {totalPages}
                    </span>
                    <button
                      onClick={() => setCurrentPage(currentPage + 1)}
                      disabled={currentPage === totalPages}
                      className="px-3 py-1 text-sm border border-gray-300 rounded hover:bg-gray-100 disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                      Next
                    </button>
                  </div>
                </div>
              </div>
            )}
          </>
        )}
      </div>

      {/* Edit User Modal */}
      {showEditModal && editingUser && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-xl p-6 max-w-md w-full mx-4">
            <h3 className="text-lg font-semibold text-gray-900 mb-4">Edit User</h3>
            
            <div className="space-y-4">
              <div className="p-3 bg-gray-50 rounded-lg">
                <div className="text-sm">
                  <div><strong>Name:</strong> {editingUser.full_name}</div>
                  <div><strong>Email:</strong> {editingUser.email}</div>
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  First Name
                </label>
                <input
                  type="text"
                  value={editingUser.first_name}
                  onChange={(e) => setEditingUser(prev => ({ ...prev, first_name: e.target.value }))}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-purple-500"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Last Name
                </label>
                <input
                  type="text"
                  value={editingUser.last_name}
                  onChange={(e) => setEditingUser(prev => ({ ...prev, last_name: e.target.value }))}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-purple-500"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">Role</label>
                <select
                  value={editingUser.role}
                  onChange={(e) => setEditingUser(prev => ({ ...prev, role: e.target.value }))}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-purple-500"
                >
                  <option value="user">User - Can request access</option>
                  <option value="admin">Admin - Can approve requests and manage users</option>
                </select>
              </div>

              <div>
                <label className="flex items-center">
                  <input
                    type="checkbox"
                    checked={editingUser.is_active}
                    onChange={(e) => setEditingUser(prev => ({ ...prev, is_active: e.target.checked }))}
                    className="rounded border-gray-300 text-purple-600 focus:ring-purple-500"
                  />
                  <span className="ml-2 text-sm text-gray-700">User is active</span>
                </label>
                <p className="text-xs text-gray-500 mt-1">
                  Inactive users cannot log in or make requests
                </p>
              </div>

              {editingUser.active_requests > 0 && !editingUser.is_active && (
                <div className="p-3 bg-yellow-50 border border-yellow-200 rounded-lg">
                  <div className="flex items-start">
                    <AlertTriangle className="w-5 h-5 text-yellow-500 mt-0.5 mr-2 flex-shrink-0" />
                    <div className="text-sm text-yellow-800">
                      <strong>Warning:</strong> This user has {editingUser.active_requests} active AWS sessions. 
                      Deactivating will prevent login but won't revoke existing access until expiration.
                    </div>
                  </div>
                </div>
              )}
            </div>

            <div className="flex items-center justify-end space-x-3 mt-6">
              <button
                onClick={() => {
                  setShowEditModal(false)
                  setEditingUser(null)
                }}
                className="px-4 py-2 text-gray-600 hover:text-gray-800 transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={() => handleUserUpdate(editingUser.user_id, {
                  first_name: editingUser.first_name,
                  last_name: editingUser.last_name,
                  role: editingUser.role,
                  is_active: editingUser.is_active
                })}
                disabled={actionLoading === editingUser.user_id}
                className="px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {actionLoading === editingUser.user_id ? "Saving..." : "Save Changes"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Delete User Modal */}
      {showDeleteModal && deletingUser && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-xl p-6 max-w-md w-full mx-4">
            <div className="flex items-center mb-4">
              <AlertTriangle className="w-6 h-6 text-red-500 mr-3" />
              <h3 className="text-lg font-semibold text-gray-900">Delete User</h3>
            </div>

            <div className="mb-4 p-3 bg-gray-50 rounded-lg">
              <div className="text-sm">
                <div><strong>Name:</strong> {deletingUser.full_name}</div>
                <div><strong>Email:</strong> {deletingUser.email}</div>
                <div><strong>Role:</strong> {deletingUser.role.toUpperCase()}</div>
                <div><strong>Status:</strong> {deletingUser.is_active ? 'Active' : 'Inactive'}</div>
              </div>
            </div>

            {deletingUser.active_requests > 0 && (
              <div className="mb-4 p-3 bg-red-50 border border-red-200 rounded-lg">
                <div className="flex items-start">
                  <AlertTriangle className="w-5 h-5 text-red-500 mt-0.5 mr-2 flex-shrink-0" />
                  <div className="text-sm text-red-800">
                    <strong>Warning:</strong> This user has {deletingUser.active_requests} active AWS sessions. 
                    Deleting will not automatically revoke their current access.
                  </div>
                </div>
              </div>
            )}

            <div className="mb-4 p-3 bg-yellow-50 border border-yellow-200 rounded-lg">
              <div className="text-sm text-yellow-800">
                <strong>Note:</strong> This will deactivate the user account. Use "Force Delete" to permanently 
                remove the user from the database.
              </div>
            </div>

            <div className="flex items-center justify-end space-x-3">
              <button
                onClick={() => {
                  setShowDeleteModal(false)
                  setDeletingUser(null)
                }}
                className="px-4 py-2 text-gray-600 hover:text-gray-800 transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={() => handleUserDelete(deletingUser.user_id, false)}
                disabled={actionLoading === deletingUser.user_id}
                className="px-4 py-2 bg-yellow-600 text-white rounded-lg hover:bg-yellow-700 transition-colors disabled:opacity-50"
              >
                {actionLoading === deletingUser.user_id ? "Processing..." : "Deactivate"}
              </button>
              <button
                onClick={() => handleUserDelete(deletingUser.user_id, true)}
                disabled={actionLoading === deletingUser.user_id}
                className="px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 transition-colors disabled:opacity-50"
              >
                {actionLoading === deletingUser.user_id ? "Processing..." : "Force Delete"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}



// Password Reset Request Component
const ForgotPasswordModal: React.FC<{
  isOpen: boolean
  onClose: () => void
  addNotification: (message: string, type: "success" | "error") => void
}> = ({ isOpen, onClose, addNotification }) => {
  const [form, setForm] = useState<ForgotPasswordForm>({ email: "" })
  const [loading, setLoading] = useState(false)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    try {
      setLoading(true)
      const response = await apiCall("/auth/forgot-password", form, "POST", false)
      if (response.status === "SUCCESS") {
        addNotification("Password reset instructions sent to your email", "success")
        onClose()
        setForm({ email: "" })
      } else {
        addNotification(response.message || "Failed to send reset email", "error")
      }
    } catch (error: any) {
      addNotification(`Error: ${error.message}`, "error")
    } finally {
      setLoading(false)
    }
  }

  if (!isOpen) return null

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white rounded-xl p-6 max-w-md w-full mx-4">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold text-gray-900">Reset Password</h3>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-gray-600"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <p className="text-gray-600 mb-4">
          Enter your email address and we'll send you a link to reset your password.
        </p>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Email Address
            </label>
            <input
              type="email"
              value={form.email}
              onChange={(e) => setForm({ ...form, email: e.target.value })}
              className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              required
              placeholder="Enter your email address"
            />
          </div>

          <div className="flex items-center justify-end space-x-3">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 text-gray-600 hover:text-gray-800 transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={loading || !form.email}
              className="bg-blue-600 text-white py-2 px-4 rounded-lg font-medium hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed flex items-center space-x-2"
            >
              {loading ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  <span>Sending...</span>
                </>
              ) : (
                <span>Send Reset Link</span>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// Change Password Component
const ChangePasswordModal: React.FC<{
  isOpen: boolean
  onClose: () => void
  addNotification: (message: string, type: "success" | "error") => void
}> = ({ isOpen, onClose, addNotification }) => {
  const [form, setForm] = useState<ChangePasswordForm>({
    currentPassword: "",
    newPassword: "",
    confirmPassword: ""
  })
  const [loading, setLoading] = useState(false)
  const [showPasswords, setShowPasswords] = useState({
    current: false,
    new: false,
    confirm: false
  })
  const [errors, setErrors] = useState<{[key: string]: string}>({})

  const validateForm = () => {
    const newErrors: {[key: string]: string} = {}
    
    if (!form.currentPassword) {
      newErrors.currentPassword = "Current password is required"
    }
    
    if (!form.newPassword) {
      newErrors.newPassword = "New password is required"
    } else if (form.newPassword.length < 8) {
      newErrors.newPassword = "Password must be at least 8 characters"
    }
    
    if (form.newPassword !== form.confirmPassword) {
      newErrors.confirmPassword = "Passwords do not match"
    }
    
    setErrors(newErrors)
    return Object.keys(newErrors).length === 0
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    
    if (!validateForm()) return

    try {
      setLoading(true)
      const response = await apiCall("/auth/change-password", {
        current_password: form.currentPassword,
        new_password: form.newPassword
      })
      
      if (response.status === "SUCCESS") {
        addNotification("Password changed successfully!", "success")
        onClose()
        setForm({ currentPassword: "", newPassword: "", confirmPassword: "" })
        setErrors({})
      } else {
        addNotification(response.message || "Failed to change password", "error")
      }
    } catch (error: any) {
      addNotification(`Error: ${error.message}`, "error")
    } finally {
      setLoading(false)
    }
  }

  if (!isOpen) return null

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white rounded-xl p-6 max-w-md w-full mx-4">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold text-gray-900">Change Password</h3>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-gray-600"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Current Password
            </label>
            <div className="relative">
              <input
                type={showPasswords.current ? "text" : "password"}
                value={form.currentPassword}
                onChange={(e) => setForm({ ...form, currentPassword: e.target.value })}
                className={`w-full px-4 py-3 pr-12 border rounded-lg focus:ring-2 transition-colors ${
                  errors.currentPassword 
                    ? 'border-red-300 focus:ring-red-500' 
                    : 'border-gray-300 focus:ring-blue-500'
                }`}
                required
              />
              <button
                type="button"
                onClick={() => setShowPasswords(prev => ({ ...prev, current: !prev.current }))}
                className="absolute inset-y-0 right-0 px-3 flex items-center"
              >
                {showPasswords.current ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
            {errors.currentPassword && (
              <p className="mt-1 text-sm text-red-600">{errors.currentPassword}</p>
            )}
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              New Password
            </label>
            <div className="relative">
              <input
                type={showPasswords.new ? "text" : "password"}
                value={form.newPassword}
                onChange={(e) => setForm({ ...form, newPassword: e.target.value })}
                className={`w-full px-4 py-3 pr-12 border rounded-lg focus:ring-2 transition-colors ${
                  errors.newPassword 
                    ? 'border-red-300 focus:ring-red-500' 
                    : 'border-gray-300 focus:ring-blue-500'
                }`}
                required
              />
              <button
                type="button"
                onClick={() => setShowPasswords(prev => ({ ...prev, new: !prev.new }))}
                className="absolute inset-y-0 right-0 px-3 flex items-center"
              >
                {showPasswords.new ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
            {errors.newPassword && (
              <p className="mt-1 text-sm text-red-600">{errors.newPassword}</p>
            )}
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Confirm New Password
            </label>
            <div className="relative">
              <input
                type={showPasswords.confirm ? "text" : "password"}
                value={form.confirmPassword}
                onChange={(e) => setForm({ ...form, confirmPassword: e.target.value })}
                className={`w-full px-4 py-3 pr-12 border rounded-lg focus:ring-2 transition-colors ${
                  errors.confirmPassword 
                    ? 'border-red-300 focus:ring-red-500' 
                    : 'border-gray-300 focus:ring-blue-500'
                }`}
                required
              />
              <button
                type="button"
                onClick={() => setShowPasswords(prev => ({ ...prev, confirm: !prev.confirm }))}
                className="absolute inset-y-0 right-0 px-3 flex items-center"
              >
                {showPasswords.confirm ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
            {errors.confirmPassword && (
              <p className="mt-1 text-sm text-red-600">{errors.confirmPassword}</p>
            )}
          </div>

          <div className="flex items-center justify-end space-x-3 pt-2">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 text-gray-600 hover:text-gray-800 transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={loading}
              className="bg-blue-600 text-white py-2 px-4 rounded-lg font-medium hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed flex items-center space-x-2"
            >
              {loading ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  <span>Changing...</span>
                </>
              ) : (
                <span>Change Password</span>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
// Role based request form component
const RoleBasedRequestForm: React.FC<{
  authState: AuthState;
  availableRoles: Role[]
  loading: boolean
  onSuccess: () => void
  addNotification: (message: string, type: "success" | "error") => void
}> = ({ authState, loading, onSuccess, addNotification, availableRoles }) => {
  const [form, setForm] = useState({
    duration_minutes: 120,
    justification: "",
    urgency: "normal",
    account_id: "",
    selected_roles: [] as string[] // Changed to array for multiple roles
  })
  const [submitting, setSubmitting] = useState(false)
  const [showRoleDropdown, setShowRoleDropdown] = useState(false)

  const handleSubmit = async () => {
    // Validation
    const errors: string[] = []
    
    if (!form.account_id) {
      errors.push("Please select an AWS account")
    }
    
    if (form.selected_roles.length === 0) {
      errors.push("Please select at least one role")
    }
    
    if (form.selected_roles.length > 5) {
      errors.push("You can select a maximum of 5 roles")
    }
    
    if (form.justification.trim().length < 10) {
      errors.push("Business justification must be at least 10 characters long")
    }
    
    if (form.duration_minutes < 60 || form.duration_minutes > 480) {
      errors.push("Duration must be between 1 and 8 hours")
    }
    
    if (errors.length > 0) {
      addNotification(errors.join(". "), "error")
      return
    }

    try {
      setSubmitting(true)
      const response = await apiCall("/request-role-access", {
        email: authState.user?.email,
        duration_minutes: form.duration_minutes,
        justification: form.justification,
        urgency: form.urgency,
        account_id: form.account_id,
        use_role_permissions: true,
        requested_roles: form.selected_roles // Send array of selected role IDs
      })

      if (response.status === "SUCCESS") {
        addNotification("Role-based access request submitted successfully!", "success")
        // Reset form
        setForm({
          duration_minutes: 120,
          justification: "",
          urgency: "normal",
          account_id: "",
          selected_roles: []
        })
        onSuccess()
      } else {
        addNotification(response.message || "Failed to submit request", "error")
      }
    } catch (error: any) {
      addNotification(`Error: ${error.message}`, "error")
    } finally {
      setSubmitting(false)
    }
  }

  const handleRoleToggle = (roleId: string) => {
    setForm(prev => {
      const isSelected = prev.selected_roles.includes(roleId)
      let newSelectedRoles: string[]
      
      if (isSelected) {
        // Remove role
        newSelectedRoles = prev.selected_roles.filter(id => id !== roleId)
      } else {
        // Add role (check max limit)
        if (prev.selected_roles.length >= 5) {
          addNotification("You can select a maximum of 5 roles", "error")
          return prev
        }
        newSelectedRoles = [...prev.selected_roles, roleId]
      }
      
      return { ...prev, selected_roles: newSelectedRoles }
    })
  }

  const getSelectedRoleNames = () => {
    return form.selected_roles.map(roleId => {
      const role = availableRoles.find(r => r.role_id === roleId)
      return role?.display_name || roleId
    }).join(", ")
  }

  return (
    <div className="space-y-6">
      <div className="bg-white rounded-xl shadow-sm border border-gray-200">
        <div className="p-6 border-b border-gray-100">
          <h3 className="text-xl font-semibold text-gray-900 flex items-center">
            <UserCheck className="w-6 h-6 mr-3 text-green-600" />
            Request Role-Based Access
          </h3>
          <p className="text-gray-600 mt-1">Request access using permissions from selected roles</p>
        </div>

        <div className="p-6 space-y-6">
          {/* Role Selection Dropdown */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Select Roles (Maximum 5) *
            </label>
            <div className="relative">
              <button
                type="button"
                onClick={() => setShowRoleDropdown(!showRoleDropdown)}
                className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-green-500 focus:border-green-500 text-left bg-white flex items-center justify-between"
              >
                <span className={form.selected_roles.length === 0 ? "text-gray-500" : "text-gray-900"}>
                  {form.selected_roles.length === 0 
                    ? "Choose roles..." 
                    : `${form.selected_roles.length} role${form.selected_roles.length > 1 ? 's' : ''} selected`
                  }
                </span>
                <ChevronDown className={`w-5 h-5 transition-transform ${showRoleDropdown ? 'rotate-180' : ''}`} />
              </button>
              
              {/* Selected roles display */}
              {form.selected_roles.length > 0 && (
                <div className="mt-2 flex flex-wrap gap-2">
                  {form.selected_roles.map(roleId => {
                    const role = availableRoles.find(r => r.role_id === roleId)
                    return (
                      <span
                        key={roleId}
                        className="inline-flex items-center px-3 py-1 rounded-full text-sm bg-green-100 text-green-800 border border-green-200"
                      >
                        {role?.display_name || roleId}
                        <button
                          type="button"
                          onClick={() => handleRoleToggle(roleId)}
                          className="ml-2 text-green-600 hover:text-green-800"
                        >
                          <X className="w-3 h-3" />
                        </button>
                      </span>
                    )
                  })}
                </div>
              )}
              
              {/* Dropdown options */}
              {showRoleDropdown && (
                <div className="absolute z-10 w-full mt-1 bg-white border border-gray-300 rounded-lg shadow-lg max-h-60 overflow-y-auto">
                  {availableRoles.map((role) => {
                    const isSelected = form.selected_roles.includes(role.role_id)
                    return (
                      <div
                        key={role.role_id}
                        onClick={() => handleRoleToggle(role.role_id)}
                        className={`flex items-start space-x-3 p-3 cursor-pointer transition-colors hover:bg-gray-50 ${
                          isSelected ? "bg-green-50" : ""
                        }`}
                      >
                        <input
                          type="checkbox"
                          checked={isSelected}
                          onChange={() => {}} // Handled by onClick above
                          className="mt-1 rounded border-gray-300 text-green-600 focus:ring-green-500"
                        />
                        <div className="flex-1">
                          <div className="font-medium text-gray-900">{role.display_name}</div>
                          {role.description && (
                            <div className="text-sm text-gray-600">{role.description}</div>
                          )}
                          <div className="text-xs text-gray-500 mt-1">
                            Role ID: <code className="bg-gray-100 px-1 rounded">{role.role_id}</code>
                          </div>
                        </div>
                      </div>
                    )
                  })}
                </div>
              )}
            </div>
            <p className="text-xs text-gray-500 mt-1">
              Select the roles whose permissions you need for this request
            </p>
          </div>

          {/* AWS Account Selector */}
          <AWSAccountSelector
            selectedAccountId={form.account_id}
            onAccountChange={(accountId) => setForm(prev => ({ ...prev, account_id: accountId }))}
            disabled={submitting}
          />

          {/* Urgency Selection */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-3">Request Urgency</label>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              {[
                { value: "low", label: "Low Priority", desc: "Can wait", icon: "🟢" },
                { value: "normal", label: "Normal", desc: "Standard timing", icon: "🟡" },
                { value: "high", label: "High Priority", desc: "Urgent business need", icon: "🟠" },
                { value: "critical", label: "Critical", desc: "Production issue", icon: "🔴" },
              ].map((urgency) => (
                <label
                  key={urgency.value}
                  className={`flex items-center p-3 rounded-lg border-2 cursor-pointer transition-all ${
                    form.urgency === urgency.value
                      ? "border-green-500 bg-green-50"
                      : "border-gray-200 hover:border-gray-300"
                  }`}
                >
                  <input
                    type="radio"
                    name="urgency"
                    value={urgency.value}
                    checked={form.urgency === urgency.value}
                    onChange={(e) => setForm((prev) => ({ ...prev, urgency: e.target.value }))}
                    className="sr-only"
                  />
                  <div className="flex-1">
                    <div className="flex items-center mb-1">
                      <span className="mr-2">{urgency.icon}</span>
                      <span className="font-medium text-sm">{urgency.label}</span>
                    </div>
                    <div className="text-xs text-gray-500">{urgency.desc}</div>
                  </div>
                </label>
              ))}
            </div>
          </div>

          {/* Duration Selection */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-3">Access Duration</label>
            <div className="space-y-4">
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                {QUICK_DURATIONS.map((duration) => (
                  <button
                    key={duration.minutes}
                    type="button"
                    onClick={() => setForm((prev) => ({ ...prev, duration_minutes: duration.minutes }))}
                    className={`p-3 rounded-lg border-2 text-center cursor-pointer transition-all ${
                      form.duration_minutes === duration.minutes
                        ? "border-green-500 bg-green-50"
                        : "border-gray-200 hover:border-gray-300"
                    }`}
                  >
                    <div className="font-medium">{duration.label}</div>
                    {duration.recommended && <div className="text-xs text-green-600 mt-1">Recommended</div>}
                  </button>
                ))}
              </div>
              <div className="flex items-center space-x-4">
                <div className="flex-1">
                  <input
                    type="range"
                    min="60"
                    max="480"
                    step="30"
                    value={form.duration_minutes}
                    onChange={(e) => setForm((prev) => ({ ...prev, duration_minutes: parseInt(e.target.value) }))}
                    className="w-full h-2 bg-gray-200 rounded-lg appearance-none cursor-pointer"
                  />
                </div>
                <div className="text-sm text-gray-600 min-w-0 font-medium">
                  {form.duration_minutes} min ({(form.duration_minutes / 60).toFixed(1)}h)
                </div>
              </div>
            </div>
          </div>

          {/* Justification */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Business Justification *</label>
            <textarea
              value={form.justification}
              onChange={(e) => setForm((prev) => ({ ...prev, justification: e.target.value }))}
              placeholder="Provide detailed justification for this role-based access request. Include what you plan to do, why it's necessary, and any relevant context..."
              rows={4}
              className="w-full border border-gray-300 rounded-lg px-4 py-3 focus:ring-2 focus:ring-green-500 focus:border-green-500 resize-none"
            />
            <div className="flex justify-between items-center mt-2">
              <div className={`text-xs ${form.justification.length < 10 ? "text-red-500" : "text-gray-500"}`}>
                {form.justification.length}/10 characters minimum
              </div>
              {form.justification.length >= 10 && (
                <div className="text-xs text-green-600 flex items-center">
                  <CheckCircle className="w-3 h-3 mr-1" />
                  Looks good!
                </div>
              )}
            </div>
          </div>

          {/* Submit Button */}
          <div className="flex items-center justify-end space-x-4 pt-4 border-t border-gray-100">
            <button
              type="button"
              onClick={() => setForm({
                duration_minutes: 120,
                justification: "",
                urgency: "normal",
                account_id: "",
                selected_roles: []
              })}
              className="px-4 py-2 text-gray-600 hover:text-gray-800 transition-colors"
            >
              Reset Form
            </button>
            <button
              onClick={handleSubmit}
              disabled={
                submitting ||
                loading ||
                !form.account_id ||
                form.selected_roles.length === 0 ||
                form.justification.length < 10
              }
              className="bg-green-600 text-white py-3 px-6 rounded-lg font-medium disabled:bg-gray-300 disabled:cursor-not-allowed hover:bg-green-700 transition-all duration-200 flex items-center space-x-2 shadow-md"
            >
              {submitting ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  <span>Submitting...</span>
                </>
              ) : (
                <>
                  <UserCheck className="w-4 h-4" />
                  <span>Request Access for {form.selected_roles.length} Role{form.selected_roles.length !== 1 ? 's' : ''}</span>
                </>
              )}
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

// AWS Account Selector Component
const AWSAccountSelector: React.FC<{
  selectedAccountId: string
  onAccountChange: (accountId: string) => void
  disabled?: boolean
}> = ({ selectedAccountId, onAccountChange, disabled = false }) => {
  const [accounts, setAccounts] = useState<any[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    loadAccounts()
  }, [])

  const loadAccounts = async () => {
    try {
      setLoading(true)
      setError(null)
      
      const response = await apiCall("/aws-accounts", null, "GET")
      
      if (response.status === "SUCCESS" && response.data?.accounts) {
        setAccounts(response.data.accounts)
      } else {
        setError("Failed to load AWS accounts")
      }
    } catch (err: any) {
      console.error("Error loading AWS accounts:", err)
      setError(`Error: ${err.message}`)
    } finally {
      setLoading(false)
    }
  }

  const handleRetry = () => {
    loadAccounts()
  }

  if (loading) {
    return (
      <div className="space-y-2">
        <label className="block text-sm font-medium text-gray-700">AWS Account *</label>
        <div className="flex items-center space-x-2 p-3 border border-gray-300 rounded-lg bg-gray-50">
          <RefreshCw className="w-4 h-4 animate-spin text-blue-600" />
          <span className="text-sm text-gray-600">Loading AWS accounts...</span>
        </div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="space-y-2">
        <label className="block text-sm font-medium text-gray-700">AWS Account *</label>
        <div className="p-3 border border-red-300 rounded-lg bg-red-50">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <AlertCircle className="w-4 h-4 text-red-500" />
              <span className="text-sm text-red-700">{error}</span>
            </div>
            <button
              onClick={handleRetry}
              disabled={loading}
              className="text-red-600 hover:text-red-800 text-sm font-medium flex items-center space-x-1"
            >
              <RefreshCw className={`w-3 h-3 ${loading ? 'animate-spin' : ''}`} />
              <span>Retry</span>
            </button>
          </div>
        </div>
      </div>
    )
  }

  if (accounts.length === 0) {
    return (
      <div className="space-y-2">
        <label className="block text-sm font-medium text-gray-700">AWS Account *</label>
        <div className="p-3 border border-yellow-300 rounded-lg bg-yellow-50">
          <div className="flex items-center space-x-2">
            <AlertTriangle className="w-4 h-4 text-yellow-600" />
            <span className="text-sm text-yellow-700">No AWS accounts available. Contact your administrator.</span>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-2">
      <label className="block text-sm font-medium text-gray-700">
        AWS Account *
        <span className="ml-2 text-xs text-gray-500">({accounts.length} available)</span>
      </label>
      <select
        value={selectedAccountId}
        onChange={(e) => onAccountChange(e.target.value)}
        disabled={disabled}
        className={`w-full px-4 py-3 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-colors ${
          disabled 
            ? 'bg-gray-100 text-gray-500 cursor-not-allowed' 
            : selectedAccountId 
              ? 'border-green-300 bg-green-50' 
              : 'border-gray-300'
        }`}
        required
      >
        <option value="">Select an AWS account...</option>
        {accounts.map((account) => (
          <option key={account.account_id} value={account.account_id}>
            {account.account_name} ({account.account_number})
          </option>
        ))}
      </select>
      
      {selectedAccountId && (
        <div className="flex items-center text-sm text-green-600">
          <CheckCircle className="w-4 h-4 mr-1" />
          Account selected
        </div>
      )}
      
      <div className="text-xs text-gray-500">
        💡 Select the AWS account where you need temporary access
      </div>
    </div>
  )
}

// Request Form Component
const RequestForm: React.FC<{
  requestForm: RequestForm
  setRequestForm: React.Dispatch<React.SetStateAction<RequestForm>>
  loading: boolean
  submitRequest: () => void
  addNotification: (message: string, type: "success" | "error") => void
  authState: AuthState,
  availableRoles:Role[]
}> = ({ requestForm, setRequestForm, loading, submitRequest, addNotification, authState, availableRoles }) => {
  const [requestMode, setRequestMode] = useState<"role" | "custom">("role")
  const [dynamicPermissions, setDynamicPermissions] = useState<Permission[]>([])
  const [loadingPermissions, setLoadingPermissions] = useState(false)
  const [expandedCategories, setExpandedCategories] = useState<{ [key: string]: boolean }>({})
  const justificationRef = useRef<HTMLTextAreaElement>(null)

  // Load dynamic permissions on mount
  useEffect(() => {
    loadPermissions()
  }, [])

  const loadPermissions = async () => {
    try {
      setLoadingPermissions(true)
      const response = await apiCall("/api/permissions", null, "GET")
      if (response.status === "SUCCESS" && response.data?.permissions) {
        setDynamicPermissions(response.data.permissions)
      } else {
        // Fallback to hardcoded permissions if API fails
        setDynamicPermissions(PERMISSIONS)
      }
    } catch (error: any) {
      console.error("Error loading permissions:", error)
      // Use hardcoded permissions as fallback
      setDynamicPermissions(PERMISSIONS)
    } finally {
      setLoadingPermissions(false)
    }
  }

  const permissionsToUse = dynamicPermissions.length > 0 ? dynamicPermissions : PERMISSIONS
  
  const groupedPermissions = permissionsToUse.reduce((acc: { [key: string]: Permission[] }, perm) => {
    if (!acc[perm.category]) {
      acc[perm.category] = []
    }
    acc[perm.category].push(perm)
    return acc
  }, {})

  const handleReloadUserRequests = async () => {
    // This will be called after successful submission
    try {
      const response = await apiCall("/user/my-requests", null, "GET")
      if (response.status === "SUCCESS") {
        // Update requests in parent component
        console.log("Requests reloaded")
      }
    } catch (error) {
      console.error("Error reloading requests:", error)
    }
  }

  const handleRoleBasedSuccess = () => {
    // Reset form and reload data
    setRequestForm({
      email: authState.user?.email || "",
      permissions: [],
      duration_minutes: 120,
      justification: "",
      urgency: "normal",
      account_id: ""
    })
    handleReloadUserRequests()
  }

  return (
    <div className="space-y-6">
      <div className="bg-white rounded-xl shadow-sm border border-gray-200">
        <div className="p-6 border-b border-gray-100">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-xl font-semibold text-gray-900 flex items-center">
                <Plus className="w-6 h-6 mr-3 text-blue-600" />
                Request Temporary Access
              </h3>
              <p className="text-gray-600 mt-1">Request elevated permissions for AWS resources with automatic expiration</p>
            </div>
            
            {/* Request Mode Toggle */}
            <div className="flex items-center space-x-3">
              <span className={`text-sm ${requestMode === 'role' ? 'text-blue-600 font-medium' : 'text-gray-500'}`}>
                Role-Based
              </span>
              <button
                onClick={() => setRequestMode(requestMode === 'role' ? 'custom' : 'role')}
                className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                  requestMode === 'custom' ? 'bg-blue-600' : 'bg-gray-300'
                }`}
              >
                <span
                  className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                    requestMode === 'custom' ? 'translate-x-6' : 'translate-x-1'
                  }`}
                />
              </button>
              <span className={`text-sm ${requestMode === 'custom' ? 'text-blue-600 font-medium' : 'text-gray-500'}`}>
                Custom Permissions
              </span>
            </div>
          </div>
        </div>

        {requestMode === "role" ? (
          <RoleBasedRequestForm
            authState={authState}
            loading={loading}
            onSuccess={handleRoleBasedSuccess}
            availableRoles={availableRoles}
            addNotification={addNotification}
          />
        ) : (
          <div className="p-6 space-y-6">
            {/* Email Input - Pre-filled and readonly */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Email Address *</label>
              <input
                type="email"
                value={requestForm.email}
                readOnly
                className="w-full border border-gray-300 rounded-lg px-4 py-3 bg-gray-50 text-gray-600"
              />
              <p className="text-xs text-gray-500 mt-1">Using your authenticated email address</p>
            </div>

            {/* AWS Account Selector */}
            <AWSAccountSelector
              selectedAccountId={requestForm.account_id}
              onAccountChange={(accountId) => 
                setRequestForm(prev => ({ ...prev, account_id: accountId }))
              }
              disabled={loading}
            />

            {/* Urgency Selection */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-3">Request Urgency</label>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                {[
                  { value: "low", label: "Low Priority", desc: "Can wait", icon: "🟢" },
                  { value: "normal", label: "Normal", desc: "Standard timing", icon: "🟡" },
                  { value: "high", label: "High Priority", desc: "Urgent business need", icon: "🟠" },
                  { value: "critical", label: "Critical", desc: "Production issue", icon: "🔴" },
                ].map((urgency) => (
                  <label
                    key={urgency.value}
                    className={`flex items-center p-3 rounded-lg border-2 cursor-pointer transition-all ${
                      requestForm.urgency === urgency.value
                        ? "border-blue-500 bg-blue-50"
                        : "border-gray-200 hover:border-gray-300"
                    }`}
                  >
                    <input
                      type="radio"
                      name="urgency"
                      value={urgency.value}
                      checked={requestForm.urgency === urgency.value}
                      onChange={(e) => setRequestForm((prev) => ({ ...prev, urgency: e.target.value }))}
                      className="sr-only"
                    />
                    <div className="flex-1">
                      <div className="flex items-center mb-1">
                        <span className="mr-2">{urgency.icon}</span>
                        <span className="font-medium text-sm">{urgency.label}</span>
                      </div>
                      <div className="text-xs text-gray-500">{urgency.desc}</div>
                    </div>
                  </label>
                ))}
              </div>
            </div>

            {/* Permissions Selection */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-3">
                Required Permissions *
                <span className="ml-2 text-xs text-gray-500">({requestForm.permissions.length} selected)</span>
              </label>
              
              {loadingPermissions && (
                <div className="mb-4 p-4 bg-blue-50 rounded-lg border border-blue-200">
                  <div className="flex items-center">
                    <RefreshCw className="w-4 h-4 animate-spin text-blue-600 mr-2" />
                    <span className="text-sm text-blue-800">Loading available permissions...</span>
                  </div>
                </div>
              )}

              <div className="space-y-4">
                {Object.entries(groupedPermissions).map(([category, perms]) => (
                  <div key={category} className="border border-gray-200 rounded-lg">
                    <button
                      type="button"
                      onClick={() =>
                        setExpandedCategories((prev) => ({
                          ...prev,
                          [category]: !prev[category],
                        }))
                      }
                      className="w-full flex items-center justify-between p-4 text-left hover:bg-gray-50"
                    >
                      <div className="flex items-center">
                        <span className="font-medium text-gray-900">{category}</span>
                        <span className="ml-2 text-sm text-gray-500">
                          ({perms.filter((p) => requestForm.permissions.includes(p.id)).length}/{perms.length})
                        </span>
                      </div>
                      {expandedCategories[category] ? (
                        <ChevronUp className="w-5 h-5" />
                      ) : (
                        <ChevronDown className="w-5 h-5" />
                      )}
                    </button>
                    {expandedCategories[category] && (
                      <div className="p-4 pt-0 space-y-3">
                        {perms.map((perm) => (
                          <label
                            key={perm.id}
                            className={`flex items-start space-x-3 p-3 rounded-lg border cursor-pointer transition-all ${
                              requestForm.permissions.includes(perm.id)
                                ? "border-blue-300 bg-blue-50"
                                : "border-gray-200 hover:border-gray-300 hover:bg-gray-50"
                            }`}
                          >
                            <input
                              type="checkbox"
                              checked={requestForm.permissions.includes(perm.id)}
                              onChange={(e) => {
                                if (e.target.checked) {
                                  setRequestForm((prev) => ({
                                    ...prev,
                                    permissions: [...prev.permissions, perm.id],
                                  }))
                                } else {
                                  setRequestForm((prev) => ({
                                    ...prev,
                                    permissions: prev.permissions.filter((p) => p !== perm.id),
                                  }))
                                }
                              }}
                              className="mt-1 rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                            />
                            <div className="flex-1">
                              <div className="flex items-center mb-1">
                                <span className="mr-2">{perm.icon}</span>
                                <span className="font-medium text-gray-900">{perm.label}</span>
                                <span
                                  className={`ml-2 px-2 py-1 rounded-full text-xs font-medium ${getRiskColor(perm.risk)}`}
                                >
                                  {perm.risk} risk
                                </span>
                              </div>
                              <div className="text-sm text-gray-600">{perm.description}</div>
                              {perm.aws_service && (
                                <div className="text-xs text-gray-500 mt-1">Service: {perm.aws_service}</div>
                              )}
                            </div>
                          </label>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>


            {/* Duration Selection */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-3">Access Duration *</label>
              <div className="space-y-4">
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                  {QUICK_DURATIONS.map((duration) => (
                    <button
                      key={duration.minutes}
                      type="button"
                      onClick={() => setRequestForm((prev) => ({ ...prev, duration_minutes: duration.minutes }))}
                      className={`p-3 rounded-lg border-2 text-center cursor-pointer transition-all ${
                        requestForm.duration_minutes === duration.minutes
                          ? "border-blue-500 bg-blue-50"
                          : "border-gray-200 hover:border-gray-300"
                      }`}
                    >
                      <div className="font-medium">{duration.label}</div>
                      {duration.recommended && <div className="text-xs text-green-600 mt-1">Recommended</div>}
                    </button>
                  ))}
                </div>
                <div className="flex items-center space-x-4">
                  <div className="flex-1">
                    <input
                      type="range"
                      min="60"
                      max="480"
                      step="30"
                      value={requestForm.duration_minutes}
                      onChange={(e) =>
                        setRequestForm((prev) => ({ ...prev, duration_minutes: Number.parseInt(e.target.value) }))
                      }
                      className="w-full h-2 bg-gray-200 rounded-lg appearance-none cursor-pointer"
                    />
                  </div>
                  <div className="text-sm text-gray-600 min-w-0 font-medium">
                    {requestForm.duration_minutes} min ({(requestForm.duration_minutes / 60).toFixed(1)}h)
                  </div>
                </div>
              </div>
            </div>

            {/* Justification */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Business Justification *</label>
              <textarea
                ref={justificationRef}
                value={requestForm.justification}
                onChange={(e) => setRequestForm((prev) => ({ ...prev, justification: e.target.value }))}
                placeholder="Provide detailed justification for this access request. Include what you plan to do, why it's necessary, and any relevant context..."
                rows={4}
                className="w-full border border-gray-300 rounded-lg px-4 py-3 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 resize-none"
              />
              <div className="flex justify-between items-center mt-2">
                <div className={`text-xs ${requestForm.justification.length < 10 ? "text-red-500" : "text-gray-500"}`}>
                  {requestForm.justification.length}/10 characters minimum
                </div>
                {requestForm.justification.length >= 10 && (
                  <div className="text-xs text-green-600 flex items-center">
                    <CheckCircle className="w-3 h-3 mr-1" />
                    Looks good!
                  </div>
                )}
              </div>
            </div>

            {/* Submit Button */}
            <div className="flex items-center justify-end space-x-4 pt-4 border-t border-gray-100">
              <button
                type="button"
                onClick={() =>
                  setRequestForm({
                    email: authState.user?.email || "",
                    permissions: [],
                    duration_minutes: 120,
                    justification: "",
                    urgency: "normal",
                    account_id: ""
                  })
                }
                className="px-4 py-2 text-gray-600 hover:text-gray-800 transition-colors"
              >
                Reset Form
              </button>
              <button
                onClick={submitRequest}
                disabled={
                  loading ||
                  !requestForm.email ||
                  !requestForm.account_id ||
                  requestForm.permissions.length === 0 ||
                  requestForm.justification.length < 10
                }
                className="bg-blue-600 text-white py-3 px-6 rounded-lg font-medium disabled:bg-gray-300 disabled:cursor-not-allowed hover:bg-blue-700 transition-all duration-200 flex items-center space-x-2 shadow-md"
              >
                {loading ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin" />
                    <span>Submitting...</span>
                  </>
                ) : (
                  <>
                    <Zap className="w-4 h-4" />
                    <span>Submit Request</span>
                  </>
                )}
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

// My Requests Component
const MyRequests: React.FC<{
  requests: any[]
  loading: boolean
  loadUserRequests: () => void
  authState: AuthState
}> = ({ requests, loading, loadUserRequests, authState }) => {
  const [searchTerm, setSearchTerm] = useState("")
  const [filterStatus, setFilterStatus] = useState("all")

  const filteredRequests = requests.filter((request) => {
    const matchesSearch =
      request.justification?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      request.permissions?.some((p: string) => p.toLowerCase().includes(searchTerm.toLowerCase()))
    const matchesStatus = filterStatus === "all" || request.status === filterStatus
    return matchesSearch && matchesStatus
  })
  const exportRequests = () => {
  const csvData = [
    ['Request ID', 'Status', 'AWS Account', 'Permissions', 'Duration (min)', 'Urgency', 'Requested Date', 'Expires At', 'Approved By', 'Justification'].join(','),
    ...filteredRequests.map(request => [
      `"${request.request_id || ''}"`,
      `"${request.status || ''}"`,
      `"${request.aws_account ? `${request.aws_account.account_name} (${request.aws_account.account_number})` : 'N/A'}"`,
      `"${request.permissions ? request.permissions.join('; ') : ''}"`,
      request.duration_minutes || 0,
      `"${request.urgency || ''}"`,
      `"${new Date(request.requested_at).toLocaleDateString()}"`,
      `"${request.expires_at ? new Date(request.expires_at).toLocaleDateString() : 'N/A'}"`,
      `"${request.approved_by || 'N/A'}"`,
      `"${(request.justification || '').replace(/"/g, '""')}"` // Escape quotes in justification
    ].join(','))
  ].join('\n')

  const blob = new Blob([csvData], { type: 'text/csv' })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = `my-requests-${new Date().toISOString().split('T')[0]}.csv`
  link.click()
  URL.revokeObjectURL(url)
}

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <h3 className="text-xl font-semibold text-gray-900 flex items-center">
          <Eye className="w-6 h-6 mr-3 text-blue-600" />
          My Access Requests
        </h3>
        <div className="flex items-center space-x-3">
          <button
            onClick={exportRequests}
            disabled={filteredRequests.length === 0}
            className="flex items-center space-x-2 px-4 py-2 text-green-600 border border-green-300 rounded-lg hover:bg-green-50 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <Download className="w-4 h-4" />
            <span>Export CSV</span>
          </button>
          <div className="relative">
            <Search className="w-4 h-4 absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400" />
            <input
              type="text"
              placeholder="Search requests..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="pl-10 pr-4 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            />
          </div>
          <select
            value={filterStatus}
            onChange={(e) => setFilterStatus(e.target.value)}
            className="px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
          >
            <option value="all">All Status</option>
            <option value="PENDING">Pending</option>
            <option value="ACTIVE">Active</option>
            <option value="APPROVED">Approved</option>
            <option value="DENIED">Denied</option>
            <option value="REVOKED">Revoked</option>
          </select>
          <button
            onClick={loadUserRequests}
            disabled={loading}
            className="text-blue-600 hover:text-blue-800 flex items-center text-sm font-medium px-3 py-2 rounded-lg hover:bg-blue-50 transition-colors disabled:opacity-50"
          >
            <RefreshCw className={`w-4 h-4 mr-1 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </button>
        </div>
      </div>

      {filteredRequests.length === 0 ? (
        <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-12 text-center">
          <div className="w-16 h-16 bg-gray-100 rounded-full flex items-center justify-center mx-auto mb-4">
            <FileText className="w-8 h-8 text-gray-400" />
          </div>
          <div className="text-gray-500 text-lg mb-2">No requests found</div>
          <div className="text-gray-400 text-sm">
            {searchTerm || filterStatus !== "all"
              ? "Try adjusting your search or filters"
              : "Submit your first access request to get started"}
          </div>
        </div>
      ) : (
        <div className="space-y-4">
          {filteredRequests.map((request) => (
            <div
              key={request.request_id}
              className="bg-white rounded-xl shadow-sm border border-gray-200 hover:shadow-md transition-shadow"
            >
              <div className="p-6">
                <div className="flex items-start justify-between mb-4">
                  <div className="flex items-center space-x-3">
                    <span
                      className={`px-3 py-1 rounded-full text-xs font-medium border ${getStatusColor(request.status)}`}
                    >
                      {request.status}
                    </span>
                    {request.urgency && (
                      <span
                        className={`px-2 py-1 rounded-full text-xs font-medium ${getUrgencyColor(request.urgency)}`}
                      >
                        {request.urgency.toUpperCase()}
                      </span>
                    )}
                    <span className="text-xs text-gray-500 flex items-center">
                      <Calendar className="w-3 h-3 mr-1" />
                      {new Date(request.requested_at).toLocaleDateString()}
                    </span>
                  </div>
                  {request.status === "ACTIVE" && request.expires_at && (
                    <div className="text-right">
                      <div className="text-xs text-gray-500">Expires</div>
                      <div className="text-sm font-medium">{new Date(request.expires_at).toLocaleString()}</div>
                    </div>
                  )}
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
                {/* ✅ NEW: AWS Account Column */}
                <div>
                  <div className="text-sm font-medium text-gray-900 mb-2">AWS Account</div>
                  <div className="space-y-1">
                    {request.aws_account ? (
                      <div className="flex items-center text-sm">
                        <div className="p-1 bg-orange-100 rounded mr-2">
                          🏢
                        </div>
                        <div>
                          <div className="font-medium text-gray-900">{request.aws_account.account_name}</div>
                          <div className="text-xs text-gray-500">({request.aws_account.account_number})</div>
                        </div>
                      </div>
                    ) : (
                      <div className="flex items-center text-sm text-gray-500">
                        <AlertTriangle className="w-4 h-4 mr-2" />
                        Account info unavailable
                      </div>
                    )}
                  </div>
                </div>

                {/* Permissions Column */}
                <div>
                  <div className="text-sm font-medium text-gray-900 mb-2">Permissions Requested</div>
                  <div className="flex flex-wrap gap-2">
                    {request.permissions?.map((perm: string) => {
                      const permData = PERMISSIONS.find((p) => p.id === perm)
                      return (
                        <span
                          key={perm}
                          className="inline-flex items-center px-2 py-1 rounded-md bg-blue-100 text-blue-800 text-xs font-medium"
                        >
                          {permData?.icon} {permData?.label || perm}
                        </span>
                      )
                    })}
                  </div>
                </div>

                {/* Duration & Status Column */}
                <div>
                  <div className="text-sm font-medium text-gray-900 mb-2">Duration & Status</div>
                  <div className="text-sm text-gray-600 space-y-1">
                    <div className="flex items-center">
                      <Timer className="w-4 h-4 mr-2" />
                      {request.duration_minutes} minutes ({(request.duration_minutes / 60).toFixed(1)} hours)
                    </div>
                    {request.status === "ACTIVE" && request.time_remaining_seconds && (
                      <div className="flex items-center text-green-600">
                        <Clock className="w-4 h-4 mr-2" />
                        {formatTimeRemaining(request.time_remaining_seconds)} remaining
                      </div>
                    )}
                    {request.approved_by && (
                      <div className="flex items-center">
                        <UserCheck className="w-4 h-4 mr-2" />
                        Approved by {request.approved_by}
                      </div>
                    )}
                  </div>
                </div>
              </div>

                {request.justification && (
                  <div className="bg-gray-50 rounded-lg p-4">
                    <div className="text-sm font-medium text-gray-900 mb-1">Justification</div>
                    <div className="text-sm text-gray-700">{request.justification}</div>
                  </div>
                )}

                {request.status === "ACTIVE" && request.user_name && (
                  <div className="mt-4 p-3 bg-green-50 rounded-lg border border-green-200">
                    <div className="text-sm text-green-800">
                      <strong>Active Session Details:</strong>
                      <br />
                      User: {request.user_name}
                    </div>
                  </div>
                )}

                {request.comments && (
                  <div className="mt-4 p-3 bg-yellow-50 rounded-lg border border-yellow-200">
                    <div className="text-sm text-yellow-800">
                      <strong>Admin Comments:</strong> {request.comments}
                    </div>
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// Approval Component
const Approvals: React.FC<{
  pendingRequests: any[]
  loading: boolean
  loadPendingRequests: () => void
  authState: AuthState
  addNotification: (message: string, type: "success" | "error") => void
}> = ({ pendingRequests, loading, loadPendingRequests, authState, addNotification }) => {
  const [processingId, setProcessingId] = useState<string | null>(null)
  const [commentModal, setCommentModal] = useState<{ 
    show: boolean
    requestId: string | null
    action: string | null
    requestDetails?: any
  }>({
    show: false,
    requestId: null,
    action: null,
    requestDetails: null
  })
  const [comment, setComment] = useState("")
  
  // New state for revoke modal
  const [revokeModal, setRevokeModal] = useState<{
    show: boolean
    requestId: string | null
    requestDetails?: any
  }>({
    show: false,
    requestId: null,
    requestDetails: null
  })
  const [revokeReason, setRevokeReason] = useState("")
  
  // New state for search and filtering
  const [searchTerm, setSearchTerm] = useState("")
  const [filterStatus, setFilterStatus] = useState("PENDING")
  const [allRequests, setAllRequests] = useState<any[]>([])
  const [showAllRequests, setShowAllRequests] = useState(false)
  const [loadingAll, setLoadingAll] = useState(false)
  
  // Pagination state
  const [currentPage, setCurrentPage] = useState(1)
  const [itemsPerPage, setItemsPerPage] = useState(10)

  // Load all requests when component mounts or when toggled
  useEffect(() => {
    if (showAllRequests) {
      loadAllRequests()
    }
  }, [showAllRequests])

  // Handle filter status when toggling between modes
  useEffect(() => {
    if (showAllRequests) {
      setFilterStatus("ALL")
    } else {
      setFilterStatus("PENDING")
    }
  }, [showAllRequests])

  const loadAllRequests = async () => {
    try {
      setLoadingAll(true)
      
      const allResponse = await apiCall("/check-status", { show_all: true })

      if (allResponse.status === "SUCCESS" && allResponse.data?.all_requests) {
        setAllRequests(allResponse.data.all_requests)
        console.log(`✅ Loaded ${allResponse.data.all_requests.length} total requests`)
      } else {
        console.log("📋 Using fallback method to load all requests")
        const [pendingResponse, activeResponse] = await Promise.all([
          apiCall("/check-status", { show_pending: true }),
          apiCall("/check-status", { show_active: true })
        ])
        
        const combined = [
          ...(pendingResponse.data?.pending_requests || []),
          ...(activeResponse.data?.active_resources || [])
        ]
        setAllRequests(combined)
        console.log(`✅ Loaded ${combined.length} requests via fallback`)
      }
    } catch (error: any) {
      console.error("Error loading all requests:", error)
      addNotification(`Error loading requests: ${error.message}`, "error")
    } finally {
      setLoadingAll(false)
    }
  }

  // Determine which requests to show based on toggle
  const requestsToFilter = showAllRequests ? allRequests : pendingRequests

  // Filter requests based on search and status
  const filteredRequests = requestsToFilter.filter((request) => {
    const matchesSearch = 
      request.justification?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      request.email?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      request.permissions?.some((p: string) => p.toLowerCase().includes(searchTerm.toLowerCase()))
    
    // Only apply status filtering when in "All Requests" mode
    // In "Pending Only" mode, pendingRequests is already pre-filtered
    const matchesStatus = showAllRequests 
      ? (filterStatus === "ALL" || request.status === filterStatus)
      : true // Skip status filtering for pending-only mode
    
    return matchesSearch && matchesStatus
  })

  // Pagination calculations
  const totalItems = filteredRequests.length
  const totalPages = Math.ceil(totalItems / itemsPerPage)
  const startIndex = (currentPage - 1) * itemsPerPage
  const endIndex = startIndex + itemsPerPage
  const paginatedRequests = filteredRequests.slice(startIndex, endIndex)
  
  // Reset to page 1 when filters change
  useEffect(() => {
    setCurrentPage(1)
  }, [searchTerm, filterStatus, showAllRequests])
  
  const exportRequests = () => {
    const dataToExport = showAllRequests ? filteredRequests : filteredRequests.filter(r => r.status === 'PENDING')
    const csvData = [
      ['Request ID', 'Email', 'Status', 'AWS Account', 'Permissions', 'Duration (min)', 'Urgency', 'Requested Date', 'Expires At', 'Approved By', 'Pending Hours', 'Justification', 'Comments'].join(','),
      ...dataToExport.map(request => [
        `"${request.request_id || ''}"`,
        `"${request.email || ''}"`,
        `"${request.status || ''}"`,
        `"${request.aws_account ? `${request.aws_account.account_name} (${request.aws_account.account_number})` : 'N/A'}"`,
        `"${request.permissions ? request.permissions.join('; ') : ''}"`,
        request.duration_minutes || 0,
        `"${request.urgency || ''}"`,
        `"${new Date(request.requested_at).toLocaleDateString()}"`,
        `"${request.expires_at ? new Date(request.expires_at).toLocaleDateString() : 'N/A'}"`,
        `"${request.approved_by || 'N/A'}"`,
        request.pending_for_hours || 'N/A',
        `"${(request.justification || '').replace(/"/g, '""')}"`,
        `"${(request.comments || '').replace(/"/g, '""')}"` 
      ].join(','))
    ].join('\n')

    const blob = new Blob([csvData], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    const filename = showAllRequests ? 'all-requests' : 'pending-requests'
    link.download = `${filename}-${new Date().toISOString().split('T')[0]}.csv`
    link.click()
    URL.revokeObjectURL(url)
  }

  // Generate page numbers for pagination
  const getPageNumbers = () => {
    const pages = []
    const maxVisiblePages = 5
    
    if (totalPages <= maxVisiblePages) {
      for (let i = 1; i <= totalPages; i++) {
        pages.push(i)
      }
    } else {
      const startPage = Math.max(1, currentPage - 2)
      const endPage = Math.min(totalPages, startPage + maxVisiblePages - 1)
      
      if (startPage > 1) {
        pages.push(1)
        if (startPage > 2) pages.push('...')
      }
      
      for (let i = startPage; i <= endPage; i++) {
        pages.push(i)
      }
      
      if (endPage < totalPages) {
        if (endPage < totalPages - 1) pages.push('...')
        pages.push(totalPages)
      }
    }
    
    return pages
  }

  // Helper function for status colors
  const getStatusColor = (status: string) => {
    switch (status) {
      case 'PENDING':
        return 'bg-yellow-100 text-yellow-800 border-yellow-300'
      case 'APPROVED':
        return 'bg-blue-100 text-blue-800 border-blue-300'
      case 'ACTIVE':
        return 'bg-green-100 text-green-800 border-green-300'
      case 'DENIED':
        return 'bg-red-100 text-red-800 border-red-300'
      case 'REVOKED':
        return 'bg-orange-100 text-orange-800 border-orange-300'
      case 'EXPIRED':
        return 'bg-gray-100 text-gray-800 border-gray-300'
      default:
        return 'bg-gray-100 text-gray-800 border-gray-300'
    }
  }

  // Helper function for urgency colors
  const getUrgencyColor = (urgency: string) => {
    switch (urgency) {
      case 'low':
        return 'bg-green-100 text-green-800'
      case 'normal':
        return 'bg-blue-100 text-blue-800'
      case 'high':
        return 'bg-orange-100 text-orange-800'
      case 'critical':
        return 'bg-red-100 text-red-800'
      default:
        return 'bg-gray-100 text-gray-800'
    }
  }

  const handleApproval = async (requestId: string, action: string, comments = "") => {
    try {
      setProcessingId(requestId)
      const response = await apiCall("/approve", {
        request_id: requestId,
        action: action,
        approver_email: authState.user?.email,
        comments: comments,
      })

      if (response.status === "SUCCESS") {
        const actionText = action === "APPROVED" ? "approved" : "denied"
        addNotification(`✅ Request ${actionText} successfully`, "success")
        await loadPendingRequests()
        if (showAllRequests) {
          await loadAllRequests()
        }
      } else {
        addNotification(response.message || "Failed to process request", "error")
      }
    } catch (error: any) {
      console.error("Error processing approval:", error)
      addNotification(`❌ Error: ${error.message}`, "error")
    } finally {
      setProcessingId(null)
      setCommentModal({ show: false, requestId: null, action: null, requestDetails: null })
      setComment("")
    }
  }

  // Updated function to open comment modal for both approve and deny
  const openCommentModal = (requestId: string, action: string, requestDetails: any) => {
    setCommentModal({ show: true, requestId, action, requestDetails })
    setComment("")
  }

  // Quick approval without comment (for urgent cases)
  const handleQuickApproval = async (requestId: string) => {
    await handleApproval(requestId, "APPROVED", "")
  }

  // New emergency revoke function
  const handleRevoke = async (requestId: string, reason: string) => {
      if (reason.trim().length < 10) {
    addNotification("❌ Revocation reason must be at least 10 characters", "error")
    return
  }
    try {
      setProcessingId(requestId)
      const response = await apiCall("/emergency-revoke", {
        request_id: requestId,
        revoker_email: authState.user?.email,
        revoke_reason: reason,
        force_revoke: false
      })

      if (response.status === "SUCCESS") {
        addNotification(`✅ Request emergency revoked successfully`, "success")
        await loadPendingRequests()
        if (showAllRequests) {
          await loadAllRequests()
        }
      } else {
        addNotification(response.message || "Failed to revoke request", "error")
      }
    } catch (error: any) {
      console.error("Error revoking request:", error)
      addNotification(`❌ Error: ${error.message}`, "error")
    } finally {
      setProcessingId(null)
      setRevokeModal({ show: false, requestId: null, requestDetails: null })
      setRevokeReason("")
    }
  }

  // Open revoke modal
  const openRevokeModal = (requestId: string, requestDetails: any) => {
    setRevokeModal({ show: true, requestId, requestDetails })
    setRevokeReason("")
  }

  return (
    <div className="space-y-6">
      {/* Header with toggle and controls */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div className="flex items-center space-x-4">
          <h3 className="text-xl font-semibold text-gray-900 flex items-center">
            <Clock className="w-6 h-6 mr-3 text-blue-600" />
            {showAllRequests ? "All Requests" : "Pending Approvals"}
          </h3>
          
          {/* Toggle switch */}
          <div className="flex items-center space-x-3">
            <span className={`text-sm ${!showAllRequests ? 'text-blue-600 font-medium' : 'text-gray-500'}`}>
              Pending Only
            </span>
            <button
              onClick={() => setShowAllRequests(!showAllRequests)}
              // disabled={loadingAll}
              className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors disabled:opacity-50 ${
                showAllRequests ? 'bg-blue-600' : 'bg-gray-300'
              }`}
            >
              <span
                className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                  showAllRequests ? 'translate-x-6' : 'translate-x-1'
                }`}
              />
            </button>
            <span className={`text-sm ${showAllRequests ? 'text-blue-600 font-medium' : 'text-gray-500'}`}>
              All Requests
            </span>
          </div>
        </div>

        <div className="flex items-center space-x-3">
          {/* Export button */}
          <button
            onClick={exportRequests}
            disabled={filteredRequests.length === 0}
            className="flex items-center space-x-2 px-4 py-2 text-green-600 border border-green-300 rounded-lg hover:bg-green-50 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <Download className="w-4 h-4" />
            <span>Export CSV</span>
          </button>
          
          {/* Search input */}
          <div className="relative">
            <Search className="w-4 h-4 absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400" />
            <input
              type="text"
              placeholder="Search requests..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="pl-10 pr-4 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            />
          </div>

          {/* Status filter */}
          <select
            value={filterStatus}
            onChange={(e) => setFilterStatus(e.target.value)}
            className="px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
          >
            {showAllRequests ? (
              <>
                <option value="ALL">All Status</option>
                <option value="PENDING">Pending</option>
                <option value="ACTIVE">Active</option>
                <option value="APPROVED">Approved</option>
                <option value="DENIED">Denied</option>
                <option value="REVOKED">Revoked</option>
                <option value="EXPIRED">Expired</option>
              </>
            ) : (
              <option value="PENDING">Pending Only</option>
            )}
          </select>

          {/* Items per page selector */}
          <select
            value={itemsPerPage}
            onChange={(e) => {
              setItemsPerPage(Number(e.target.value))
              setCurrentPage(1)
            }}
            className="px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
          >
            <option value={5}>5 per page</option>
            <option value={10}>10 per page</option>
            <option value={25}>25 per page</option>
            <option value={50}>50 per page</option>
            <option value={100}>100 per page</option>
          </select>

          {/* Refresh button */}
          <button
            onClick={() => {
              loadPendingRequests()
              if (showAllRequests) {
                loadAllRequests()
              }
            }}
            disabled={loading || loadingAll}
            className="text-blue-600 hover:text-blue-800 flex items-center text-sm font-medium px-3 py-2 rounded-lg hover:bg-blue-50 transition-colors disabled:opacity-50"
          >
            <RefreshCw className={`w-4 h-4 mr-1 ${(loading || loadingAll) ? "animate-spin" : ""}`} />
            Refresh
          </button>
        </div>
      </div>

      {/* Loading indicator */}
      {loadingAll && (
        <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
          <div className="flex items-center text-blue-800">
            <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
            <span className="text-sm">Loading all requests...</span>
          </div>
        </div>
      )}

      {/* Results summary with pagination info */}
      {showAllRequests && !loadingAll && (
        <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
          <div className="flex items-center justify-between text-sm">
            <span className="text-blue-800">
              Showing {startIndex + 1}-{Math.min(endIndex, totalItems)} of {totalItems} requests
              {requestsToFilter.length !== totalItems && (
                <span className="text-blue-600"> (filtered from {requestsToFilter.length} total)</span>
              )}
            </span>
            <span className="text-blue-600">
              {requestsToFilter.filter(r => r.status === 'PENDING').length} pending approval
            </span>
          </div>
        </div>
      )}

      {/* Pagination info for pending only view */}
      {!showAllRequests && totalItems > itemsPerPage && (
        <div className="bg-gray-50 border border-gray-200 rounded-lg p-4">
          <div className="flex items-center justify-between text-sm">
            <span className="text-gray-800">
              Showing {startIndex + 1}-{Math.min(endIndex, totalItems)} of {totalItems} pending requests
            </span>
            <span className="text-gray-600">
              Page {currentPage} of {totalPages}
            </span>
          </div>
        </div>
      )}

      {/* Requests list */}
      {totalItems === 0 && !loadingAll ? (
        <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-12 text-center">
          <div className="w-16 h-16 bg-gray-100 rounded-full flex items-center justify-center mx-auto mb-4">
            <Clock className="w-8 h-8 text-gray-400" />
          </div>
          <div className="text-gray-500 text-lg mb-2">
            {searchTerm || filterStatus !== "PENDING" ? "No requests found" : "No pending requests"}
          </div>
          <div className="text-gray-400 text-sm">
            {searchTerm || filterStatus !== "PENDING" 
              ? "Try adjusting your search or filters" 
              : "All requests have been processed"}
          </div>
        </div>
      ) : (
        <>
          <div className="space-y-4">
            {paginatedRequests.map((request) => {
              // Force status to PENDING for pending-only mode
              const displayRequest = showAllRequests 
                ? request 
                : { ...request, status: 'PENDING' }
                
              return (
                <div
                  key={request.request_id}
                  className="bg-white rounded-xl shadow-sm border border-gray-200 hover:shadow-md transition-shadow"
                >
                  <div className="p-6">
                    <div className="flex items-start justify-between mb-4">
                      <div className="flex items-center space-x-3">
                        <span
                          className={`px-3 py-1 rounded-full text-xs font-medium border ${getStatusColor(displayRequest.status)}`}
                        >
                          {displayRequest.status}
                        </span>
                        {request.urgency && (
                          <span
                            className={`px-2 py-1 rounded-full text-xs font-medium ${getUrgencyColor(request.urgency)}`}
                          >
                            {request.urgency.toUpperCase()}
                          </span>
                        )}
                        <span className="text-xs text-gray-500">
                          Requested by: <strong>{request.email}</strong>
                        </span>
                      </div>
                      <div className="text-xs text-gray-500 text-right">
                        <div>{new Date(request.requested_at).toLocaleDateString()}</div>
                        {request.pending_for_hours && (
                          <div className="text-orange-600">Pending {request.pending_for_hours}h</div>
                        )}
                      </div>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
                      {/* AWS Account Column */}
                      <div>
                        <div className="text-sm font-medium text-gray-900 mb-2">AWS Account</div>
                        <div className="space-y-1">
                          {request.aws_account ? (
                            <div className="flex items-center text-sm">
                              <div className="p-1 bg-orange-100 rounded mr-2">
                                🏢
                              </div>
                              <div>
                                <div className="font-medium text-gray-900">{request.aws_account.account_name}</div>
                                <div className="text-xs text-gray-500">({request.aws_account.account_number})</div>
                              </div>
                            </div>
                          ) : (
                            <div className="flex items-center text-sm text-gray-500">
                              <AlertTriangle className="w-4 h-4 mr-2" />
                              Account info unavailable
                            </div>
                          )}
                        </div>
                      </div>
                      <div>
                        <div className="text-sm font-medium text-gray-900 mb-2">Requested Permissions</div>
                        <div className="flex flex-wrap gap-2">
                          {request.permissions?.map((perm: string) => {
                            const permData = PERMISSIONS.find((p) => p.id === perm)
                            return (
                              <span
                                key={perm}
                                className="inline-flex items-center px-2 py-1 rounded-md bg-blue-100 text-blue-800 text-xs font-medium"
                              >
                                {permData?.icon} {permData?.label || perm}
                              </span>
                            )
                          })}
                        </div>
                      </div>
                      <div>
                        <div className="text-sm font-medium text-gray-900 mb-2">Duration & Details</div>
                        <div className="text-sm text-gray-600 space-y-1">
                          <div className="flex items-center">
                            <Timer className="w-4 h-4 mr-2" />
                            {request.duration_minutes} minutes ({(request.duration_minutes / 60).toFixed(1)} hours)
                          </div>
                          {request.approved_by && (
                            <div className="flex items-center text-green-600">
                              <UserCheck className="w-4 h-4 mr-2" />
                              Approved by {request.approved_by}
                            </div>
                          )}
                          {request.status === "ACTIVE" && request.time_remaining_seconds && (
                            <div className="flex items-center text-green-600">
                              <Clock className="w-4 h-4 mr-2" />
                              {formatTimeRemaining(request.time_remaining_seconds)} remaining
                            </div>
                          )}
                        </div>
                      </div>
                    </div>

                    {request.justification && (
                      <div className="bg-gray-50 rounded-lg p-4 mb-4">
                        <div className="text-sm font-medium text-gray-900 mb-1">Business Justification</div>
                        <div className="text-sm text-gray-700">{request.justification}</div>
                      </div>
                    )}

                    {request.comments && (
                      <div className="mb-4 p-3 bg-yellow-50 rounded-lg border border-yellow-200">
                        <div className="text-sm text-yellow-800">
                          <strong>Admin Comments:</strong> {request.comments}
                        </div>
                      </div>
                    )}

                    {/* Action buttons with consistent sizing */}
                    {(request.status === "PENDING" || !showAllRequests) && (
                      <div className="flex items-center justify-end space-x-3 pt-4 border-t border-gray-100">
                        {/* Quick Approve */}
                        <button
                          onClick={() => handleQuickApproval(request.request_id)}
                          disabled={processingId === request.request_id}
                          className="px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 transition-colors font-medium disabled:opacity-50 flex items-center space-x-2 min-w-[120px] justify-center"
                        >
                          {processingId === request.request_id ? (
                            <>
                              <RefreshCw className="w-4 h-4 animate-spin" />
                              <span>Processing...</span>
                            </>
                          ) : (
                            <>
                              <CheckCircle className="w-4 h-4" />
                              <span>Quick Approve</span>
                            </>
                          )}
                        </button>

                        {/* Approve with Comment */}
                        <button
                          onClick={() => openCommentModal(request.request_id, "APPROVED", request)}
                          disabled={processingId === request.request_id}
                          className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors font-medium disabled:opacity-50 flex items-center space-x-2 min-w-[120px] justify-center"
                        >
                          <FileText className="w-4 h-4" />
                          <span>Approve with Comment</span>
                        </button>

                        {/* Deny */}
                        <button
                          onClick={() => openCommentModal(request.request_id, "DENIED", request)}
                          disabled={processingId === request.request_id}
                          className="px-4 py-2 text-red-600 border border-red-300 rounded-lg hover:bg-red-50 transition-colors font-medium disabled:opacity-50 flex items-center space-x-2 min-w-[120px] justify-center"
                        >
                          <XCircle className="w-4 h-4" />
                          <span>Deny</span>
                        </button>
                      </div>
                    )}

                    {/* Emergency Revoke button for APPROVED or ACTIVE requests */}
                    {(request.status === "APPROVED" || request.status === "ACTIVE") && (
                      <div className="flex items-center justify-end space-x-3 pt-4 border-t border-gray-100">
                        <button
                          onClick={() => openRevokeModal(request.request_id, request)}
                          disabled={processingId === request.request_id}
                          className="px-4 py-2 text-orange-600 border border-orange-300 rounded-lg hover:bg-orange-50 transition-colors font-medium disabled:opacity-50 flex items-center space-x-2 min-w-[140px] justify-center"
                        >
                          <AlertTriangle className="w-4 h-4" />
                          <span>Emergency Revoke</span>
                        </button>
                      </div>
                    )}

                    {/* Info for completed requests */}
                    {(request.status === "DENIED" || request.status === "REVOKED" || request.status === "EXPIRED") && (
                      <div className="pt-4 border-t border-gray-100">
                        <div className="text-sm text-gray-500 text-center">
                          {request.status === "DENIED" && "Request was denied by administrator"}
                          {request.status === "REVOKED" && request.emergency_revoked && "Access was emergency revoked by administrator"}
                          {request.status === "REVOKED" && !request.emergency_revoked && "Access was revoked on expiry"}
                          {request.status === "EXPIRED" && "Access was revoked on expiry"}
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              )
            })}
          </div>

          {/* Pagination Controls */}
          {totalPages > 1 && (
            <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-4">
              <div className="flex items-center justify-between">
                <div className="text-sm text-gray-700">
                  Showing <span className="font-medium">{startIndex + 1}</span> to{' '}
                  <span className="font-medium">{Math.min(endIndex, totalItems)}</span> of{' '}
                  <span className="font-medium">{totalItems}</span> results
                </div>

                <div className="flex items-center space-x-2">
                  <button
                    onClick={() => setCurrentPage(currentPage - 1)}
                    disabled={currentPage === 1}
                    className="px-3 py-2 text-sm font-medium text-gray-500 bg-white border border-gray-300 rounded-md hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    Previous
                  </button>

                  <div className="flex items-center space-x-1">
                    {getPageNumbers().map((page, index) => (
                      <button
                        key={index}
                        onClick={() => typeof page === 'number' && setCurrentPage(page)}
                        disabled={page === '...'}
                        className={`px-3 py-2 text-sm font-medium rounded-md ${
                          page === currentPage
                            ? 'text-blue-600 bg-blue-50 border border-blue-300'
                            : page === '...'
                            ? 'text-gray-400 cursor-default'
                            : 'text-gray-700 bg-white border border-gray-300 hover:bg-gray-50'
                        }`}
                      >
                        {page}
                      </button>
                    ))}
                  </div>

                  <button
                    onClick={() => setCurrentPage(currentPage + 1)}
                    disabled={currentPage === totalPages}
                    className="px-3 py-2 text-sm font-medium text-gray-500 bg-white border border-gray-300 rounded-md hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    Next
                  </button>
                </div>
              </div>

              {/* Jump to page */}
              {totalPages > 10 && (
                <div className="mt-4 pt-4 border-t border-gray-200">
                  <div className="flex items-center justify-center space-x-2">
                    <span className="text-sm text-gray-600">Jump to page:</span>
                    <input
                      type="number"
                      min="1"
                      max={totalPages}
                      value={currentPage}
                      onChange={(e) => {
                        const page = parseInt(e.target.value)
                        if (page >= 1 && page <= totalPages) {
                          setCurrentPage(page)
                        }
                      }}
                      className="w-16 px-2 py-1 text-sm border border-gray-300 rounded focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                    />
                    <span className="text-sm text-gray-600">of {totalPages}</span>
                  </div>
                </div>
              )}
            </div>
          )}
        </>
      )}

      {/* Comment Modal - Enhanced for both approve and deny */}
      {commentModal.show && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-xl p-6 max-w-md w-full mx-4">
            <div className="flex items-center mb-4">
              {commentModal.action === "DENIED" ? (
                <XCircle className="w-6 h-6 text-red-500 mr-3" />
              ) : (
                <CheckCircle className="w-6 h-6 text-green-500 mr-3" />
              )}
              <h3 className="text-lg font-semibold text-gray-900">
                {commentModal.action === "DENIED" ? "Deny Request" : "Approve Request"}
              </h3>
            </div>

            {/* Request details summary */}
            {commentModal.requestDetails && (
              <div className="mb-4 p-3 bg-gray-50 rounded-lg">
                <div className="text-sm">
                  <div><strong>Requester:</strong> {commentModal.requestDetails.email}</div>
                  <div><strong>Duration:</strong> {commentModal.requestDetails.duration_minutes} minutes</div>
                  <div><strong>Urgency:</strong> {commentModal.requestDetails.urgency?.toUpperCase()}</div>
                </div>
              </div>
            )}

            <div className="mb-4">
              <label className="block text-sm font-medium text-gray-700 mb-2">
                {commentModal.action === "DENIED" ? "Reason for denial: *" : "Comments (optional):"}
              </label>
              <textarea
                value={comment}
                onChange={(e) => setComment(e.target.value)}
                placeholder={
                  commentModal.action === "DENIED" 
                    ? "Please provide a clear reason for denial..." 
                    : "Add any approval comments or conditions..."
                }
                rows={3}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              />
              {commentModal.action === "DENIED" && (
                <p className="text-xs text-red-600 mt-1">* Required for denials</p>
              )}
            </div>

            <div className="flex items-center justify-end space-x-3">
              <button
                onClick={() => setCommentModal({ show: false, requestId: null, action: null, requestDetails: null })}
                className="px-4 py-2 text-gray-600 hover:text-gray-800 transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={() =>
                  commentModal.requestId &&
                  commentModal.action &&
                  handleApproval(commentModal.requestId, commentModal.action, comment)
                }
                disabled={commentModal.action === "DENIED" && !comment.trim()}
                className={`px-4 py-2 rounded-lg font-medium transition-colors disabled:opacity-50 flex items-center space-x-2 ${
                  commentModal.action === "DENIED"
                    ? "bg-red-600 text-white hover:bg-red-700"
                    : "bg-green-600 text-white hover:bg-green-700"
                }`}
              >
                {commentModal.action === "DENIED" ? (
                  <>
                    <XCircle className="w-4 h-4" />
                    <span>Deny Request</span>
                  </>
                ) : (
                  <>
                    <CheckCircle className="w-4 h-4" />
                    <span>Approve Request</span>
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Emergency Revoke Modal */}
      {revokeModal.show && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-xl p-6 max-w-md w-full mx-4">
            <div className="flex items-center mb-4">
              <AlertTriangle className="w-6 h-6 text-orange-500 mr-3" />
              <h3 className="text-lg font-semibold text-gray-900">Emergency Revoke Access</h3>
            </div>

            {/* Request details summary */}
            {revokeModal.requestDetails && (
              <div className="mb-4 p-3 bg-orange-50 rounded-lg border border-orange-200">
                <div className="text-sm">
                  <div><strong>User:</strong> {revokeModal.requestDetails.email}</div>
                  <div><strong>Status:</strong> {revokeModal.requestDetails.status}</div>
                  <div><strong>AWS Account:</strong> {revokeModal.requestDetails.aws_account?.account_name}</div>
                  {revokeModal.requestDetails.status === "ACTIVE" && revokeModal.requestDetails.time_remaining_seconds && (
                    <div><strong>Time Remaining:</strong> {formatTimeRemaining(revokeModal.requestDetails.time_remaining_seconds)}</div>
                  )}
                </div>
              </div>
            )}

            <div className="mb-4 p-3 bg-red-50 rounded-lg border border-red-200">
              <div className="flex items-start">
                <AlertTriangle className="w-5 h-5 text-red-500 mt-0.5 mr-2 flex-shrink-0" />
                <div className="text-sm text-red-800">
                  <strong>Warning:</strong> This will immediately revoke all active permissions for this request. 
                  The user will lose access instantly and be notified of the revocation.
                </div>
              </div>
            </div>

            <div className="mb-4">
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Reason for emergency revocation: *
              </label>
              <textarea
                value={revokeReason}
                onChange={(e) => setRevokeReason(e.target.value)}
                placeholder="Explain why this access needs to be revoked immediately (e.g., security incident, policy violation, user departure, etc.)"
                rows={3}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-orange-500 focus:border-orange-500"
              />
              <p className="text-xs text-gray-600 mt-1">This reason will be logged and sent to the user</p>
            </div>

            <div className="flex items-center justify-end space-x-3">
              <button
                onClick={() => setRevokeModal({ show: false, requestId: null, requestDetails: null })}
                className="px-4 py-2 text-gray-600 hover:text-gray-800 transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={() =>
                  revokeModal.requestId &&
                  handleRevoke(revokeModal.requestId, revokeReason)
                }
                disabled={!revokeReason.trim() || revokeReason.trim().length < 10 || processingId === revokeModal.requestId}
                // disabled={!revokeReason.trim() || processingId === revokeModal.requestId}
                className="px-4 py-2 bg-orange-600 text-white rounded-lg hover:bg-orange-700 transition-colors font-medium disabled:opacity-50 flex items-center space-x-2"
              >
                {processingId === revokeModal.requestId ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin" />
                    <span>Revoking...</span>
                  </>
                ) : (
                  <>
                    <AlertTriangle className="w-4 h-4" />
                    <span>Emergency Revoke</span>
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

// Simple Dashboard Component
const Dashboard: React.FC<{ statusData: StatusData; authState: AuthState; connectionStatus: ConnectionStatus }> = ({
  statusData,
  authState,
  connectionStatus,
}) => (
  <div className="space-y-6">
    <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
      <div className="bg-gradient-to-r from-blue-50 to-blue-100 rounded-xl p-6 border border-blue-200">
        <div className="flex items-center">
          <div className="p-3 bg-blue-200 rounded-lg mr-4">
            <Activity className="w-8 h-8 text-blue-600" />
          </div>
          <div>
            <div className="text-2xl font-bold text-gray-900">{statusData.summary.active || 0}</div>
            <div className="text-sm text-gray-600">Active Sessions</div>
          </div>
        </div>
      </div>
      <div className="bg-gradient-to-r from-yellow-50 to-yellow-100 rounded-xl p-6 border border-yellow-200">
        <div className="flex items-center">
          <div className="p-3 bg-yellow-200 rounded-lg mr-4">
            <Clock className="w-8 h-8 text-yellow-600" />
          </div>
          <div>
            <div className="text-2xl font-bold text-gray-900">{statusData.summary.pending || 0}</div>
            <div className="text-sm text-gray-600">Pending Requests</div>
          </div>
        </div>
      </div>
      <div className="bg-gradient-to-r from-red-50 to-red-100 rounded-xl p-6 border border-red-200">
        <div className="flex items-center">
          <div className="p-3 bg-red-200 rounded-lg mr-4">
            <AlertTriangle className="w-8 h-8 text-red-600" />
          </div>
          <div>
            <div className="text-2xl font-bold text-gray-900">{statusData.summary.urgent || 0}</div>
            <div className="text-sm text-gray-600">Urgent Requests</div>
          </div>
        </div>
      </div>
    </div>

    <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
      <h3 className="text-lg font-semibold text-gray-900 mb-4">Welcome to QTEAM System</h3>
      <p className="text-gray-600 mb-4">
        The Temporary Elevated Access Management (QTEAM) system allows you to request and manage temporary elevated
        permissions for AWS resources.
      </p>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
        <div className="p-4 bg-blue-50 rounded-lg">
          <h4 className="font-medium text-blue-900 mb-2">For End Users</h4>
          <p className="text-sm text-blue-700">
            Request temporary access to AWS resources with proper justification and automatic expiration.
          </p>
        </div>
        <div className="p-4 bg-green-50 rounded-lg">
          <h4 className="font-medium text-green-900 mb-2">For Administrators</h4>
          <p className="text-sm text-green-700">
            Review and approve access requests with full visibility into permissions and justifications.
          </p>
        </div>
      </div>

      <div className="border-t border-gray-200 pt-4">
        <h4 className="font-medium text-gray-900 mb-2">System Status</h4>
        <div className="flex items-center space-x-4 text-sm">
          <div className="flex items-center">
            <div
              className={`w-2 h-2 rounded-full mr-2 ${connectionStatus.isConnected ? "bg-green-500" : "bg-red-500"}`}
            ></div>
            <span className="text-gray-600">API: {connectionStatus.isConnected ? "Connected" : "Disconnected"}</span>
          </div>
          <div className="text-gray-500">
            Last checked:{" "}
            {connectionStatus.lastChecked ? new Date(connectionStatus.lastChecked).toLocaleTimeString() : "Never"}
          </div>
        </div>
      </div>
    </div>
  </div>
)

// Admin Dashboard Component
const AdminDashboard: React.FC<{
  statusData: StatusData
  addNotification: (message: string, type: "success" | "error") => void
  connectionStatus: ConnectionStatus
}> = ({ statusData, addNotification, connectionStatus }) => {
  const [cleanupLoading, setCleanupLoading] = useState(false)

  const handleCleanup = async () => {
    try {
      setCleanupLoading(true)
      const response = await apiCall("/scheduled-cleanup", {})
      if (response.status === "SUCCESS") {
        addNotification("Cleanup completed successfully", "success")
      } else {
        addNotification(response.message || "Cleanup failed", "error")
      }
    } catch (error: any) {
      console.error("Error triggering cleanup:", error)
      addNotification(`Cleanup error: ${error.message}`, "error")
    } finally {
      setCleanupLoading(false)
    }
  }

  const testHealthCheck = async () => {
    try {
      const response = await apiCall("/health", null, "GET", false)
      if (response.status === "SUCCESS") {
        addNotification("Health check passed - System is healthy", "success")
      } else {
        addNotification("Health check failed", "error")
      }
    } catch (error: any) {
      addNotification(`Health check error: ${error.message}`, "error")
    }
  }

  return (
    <div className="space-y-6">
      <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
        <h3 className="text-xl font-semibold text-gray-900 mb-4 flex items-center">
          <Settings className="w-6 h-6 mr-3 text-blue-600" />
          System Administration
        </h3>
        <p className="text-gray-600 mb-6">Manage system settings, monitor health, and perform maintenance operations</p>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          <div className="p-6 border border-gray-200 rounded-xl hover:shadow-md transition-shadow">
            <div className="flex items-center mb-3">
              <div className="p-2 bg-green-100 rounded-lg mr-3">
                <Activity className="w-6 h-6 text-green-600" />
              </div>
              <h4 className="font-semibold text-gray-900">Health Check</h4>
            </div>
            <p className="text-sm text-gray-600 mb-4">Test system connectivity and health</p>
            <button
              onClick={testHealthCheck}
              className="bg-green-600 text-white px-4 py-2 rounded-lg text-sm font-medium hover:bg-green-700 transition-colors w-full"
            >
              Run Health Check
            </button>
          </div>

          <div className="p-6 border border-gray-200 rounded-xl hover:shadow-md transition-shadow">
            <div className="flex items-center mb-3">
              <div className="p-2 bg-orange-100 rounded-lg mr-3">
                <Trash2 className="w-6 h-6 text-orange-600" />
              </div>
              <h4 className="font-semibold text-gray-900">System Cleanup</h4>
            </div>
            <p className="text-sm text-gray-600 mb-4">Manually trigger cleanup operations</p>
            <button
              onClick={handleCleanup}
              disabled={cleanupLoading}
              className="bg-orange-600 text-white px-4 py-2 rounded-lg text-sm font-medium hover:bg-orange-700 transition-colors w-full disabled:opacity-50 flex items-center justify-center space-x-2"
            >
              {cleanupLoading ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  <span>Running...</span>
                </>
              ) : (
                <span>Run Cleanup</span>
              )}
            </button>
          </div>


          {/* // Add this button to your existing AdminDashboard component */}
          {/* Insert this in the grid with other admin actions: */}
          <div className="p-6 border border-gray-200 rounded-xl hover:shadow-md transition-shadow">
            <div className="flex items-center mb-3">
              <div className="p-2 bg-purple-100 rounded-lg mr-3">
                <Settings className="w-6 h-6 text-purple-600" />
              </div>
              <h4 className="font-semibold text-gray-900">Initialize Database</h4>
            </div>
            <p className="text-sm text-gray-600 mb-4">Set up roles and permissions (one-time setup)</p>
            <button
              onClick={async () => {
                try {
                  const response = await apiCall("/admin/initialize-database")
                  if (response.status === "SUCCESS") {
                    addNotification("Database initialized successfully!", "success")
                  } else {
                    addNotification("Database initialization failed", "error")
                  }
                } catch (error: any) {
                  addNotification(`Error: ${error.message}`, "error")
                }
              }}
              className="bg-purple-600 text-white px-4 py-2 rounded-lg text-sm font-medium hover:bg-purple-700 transition-colors w-full"
            >
              Initialize Database
            </button>
          </div>

          <div className="p-6 border border-gray-200 rounded-xl hover:shadow-md transition-shadow">
            <div className="flex items-center mb-3">
              <div className="p-2 bg-blue-100 rounded-lg mr-3">
                <Download className="w-6 h-6 text-blue-600" />
              </div>
              <h4 className="font-semibold text-gray-900">API Documentation</h4>
            </div>
            <p className="text-sm text-gray-600 mb-4">View interactive API documentation</p>
            <button
              onClick={() => window.open(`${API_CONFIG.BASE_URL}/docs`, "_blank")}
              className="bg-blue-600 text-white px-4 py-2 rounded-lg text-sm font-medium hover:bg-blue-700 transition-colors w-full"
            >
              Open Swagger UI
            </button>
          </div>
        </div>
      </div>

      <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
        <h3 className="text-xl font-semibold text-gray-900 mb-4 flex items-center">
          <BarChart3 className="w-6 h-6 mr-3 text-purple-600" />
          System Statistics
        </h3>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-6">
          <div className="text-center p-4 bg-blue-50 rounded-lg">
            <div className="text-3xl font-bold text-blue-600">{statusData.summary.active || 0}</div>
            <div className="text-sm text-gray-600 mt-1">Active Sessions</div>
          </div>
          <div className="text-center p-4 bg-yellow-50 rounded-lg">
            <div className="text-3xl font-bold text-yellow-600">{statusData.summary.pending || 0}</div>
            <div className="text-sm text-gray-600 mt-1">Pending Requests</div>
          </div>
          <div className="text-center p-4 bg-red-50 rounded-lg">
            <div className="text-3xl font-bold text-red-600">{statusData.summary.urgent || 0}</div>
            <div className="text-sm text-gray-600 mt-1">Urgent Requests</div>
          </div>
          <div className="text-center p-4 bg-green-50 rounded-lg">
            <div className={`text-3xl font-bold ${connectionStatus.isConnected ? "text-green-600" : "text-red-600"}`}>
              {connectionStatus.isConnected ? "✓" : "✗"}
            </div>
            <div className="text-sm text-gray-600 mt-1">API Status</div>
          </div>
        </div>
      </div>

      <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">System Information</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
          <div>
            <span className="font-medium text-gray-700">Connection Status:</span>
            <div className={`mt-1 ${connectionStatus.isConnected ? "text-green-600" : "text-red-600"}`}>
              {connectionStatus.isConnected ? "Connected" : "Disconnected"}
            </div>
          </div>
          <div>
            <span className="font-medium text-gray-700">Last Health Check:</span>
            <div className="text-gray-600 mt-1">
              {connectionStatus.lastChecked ? new Date(connectionStatus.lastChecked).toLocaleString() : "Never"}
            </div>
          </div>
          <div>
            <span className="font-medium text-gray-700">Active Sessions:</span>
            <div className="text-gray-600 mt-1">{statusData.summary.active || 0} users with temporary access</div>
          </div>
          <div>
            <span className="font-medium text-gray-700">Pending Approvals:</span>
            <div className="text-gray-600 mt-1">{statusData.summary.pending || 0} requests awaiting review</div>
          </div>
        </div>
      </div>
    </div>
  )
}


// Main TEAM System Component
const TEAMSystem: React.FC = () => {
  const [authState, setAuthState] = useState<AuthState>({
    isAuthenticated: false,
    user: null,
    token: null,
  })
  const [availableRoles, setAvailableRoles] = useState<Role[]>([])
  const loadAvailableRoles = async () => {
  try {
    console.log("Loading available roles...")
    const response = await apiCall("/api/roles", null, "GET");
    console.log("response: ", response)

    if (response.status === "SUCCESS" && response.data?.roles) {
      setAvailableRoles(response.data.roles)
      console.log("Loaded roles:", response.data.roles)
    } else {
      console.log("No roles data in response:", response)
    }
  } catch (error: any) {
    console.error("Error loading roles:", error)
  }
}
  const [loginForm, setLoginForm] = useState<LoginForm>({
    email: "",
    password: "",
  })
  const [signupForm, setSignupForm] = useState({
    email: "",
    password: "",
    confirmPassword: "",
    first_name: "",
    last_name: "",
    token: "",
  })
  const [signupToken, setSignupToken] = useState<string | null>(null)
  const [validatingToken, setValidatingToken] = useState(false)
  const [tokenEmail, setTokenEmail] = useState("")
  const [activeTab, setActiveTab] = useState<string>("dashboard")
  const [requests, setRequests] = useState<any[]>([])
  const [pendingRequests, setPendingRequests] = useState<any[]>([])
  const [loading, setLoading] = useState<boolean>(false)
  const [notifications, setNotifications] = useState<Notification[]>([])
  const [connectionStatus, setConnectionStatus] = useState<ConnectionStatus>({
    isConnected: false,
    lastChecked: null,
  })

  // Request Form State
const [requestForm, setRequestForm] = useState<RequestForm>({
  email: "",
  permissions: [],
  duration_minutes: 120,
  justification: "",
  urgency: "normal",
  account_id: ""
})


  // Status Data
  const [statusData, setStatusData] = useState<StatusData>({
    active: [],
    pending: [],
    summary: { active: 0, pending: 0, urgent: 0 },
  })

  // Check for signup token in URL on mount
  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search)
    const token = urlParams.get("token")
    if (token) {
      validateSignupToken(token)
    } else {
      // Check for existing auth token
      const authToken = getAuthToken()
      if (authToken) {
        verifyToken(authToken)
      }
    }
  }, [])

  // Auto-update email when user changes
  useEffect(() => {
    if (authState.user) {
      setRequestForm((prev) => ({ ...prev, email: authState.user?.email || "" }))
    }
  }, [authState.user])

  useEffect(() => {
    if (authState.isAuthenticated) {
      loadInitialData()
      checkConnection()
      loadAvailableRoles() 

      // Set up periodic connection check
      const connectionInterval = setInterval(checkConnection, 300000) // Check every 5 minutes

      return () => clearInterval(connectionInterval)
    }
  }, [authState.isAuthenticated])

  useEffect(() => {
    if (authState.user?.role === "user" && activeTab === "dashboard") {
      setActiveTab("request")
    }
  }, [authState.user?.role])

  const validateSignupToken = async (token: string) => {
    try {
      setValidatingToken(true)
      const response = await apiCall("/auth/validate-signup-token", { token }, "POST", false)
      if (response.status === "SUCCESS") {
        setSignupToken(token)
        setTokenEmail(response.data.email || "")
        setSignupForm((prev) => ({ ...prev, token, email: response.data.email || "" }))
      } else {
        addNotification("Invalid or expired signup token", "error")
      }
    } catch (error: any) {
      addNotification(`Token validation error: ${error.message}`, "error")
    } finally {
      setValidatingToken(false)
    }
  }

  const verifyToken = async (token: string) => {
    try {
      const response = await apiCall("/auth/me", null, "GET", true)

      if (response.status === "SUCCESS") {
        setAuthState({
          isAuthenticated: true,
          user: response.data,
          token,
        })
      } else {
        // token invalid on the server → force logout
        removeAuthToken()
      }
    } catch (error: any) {
      console.error("Token verification failed:", error)

      // Network-level failure: keep the token and mark the app offline
      if (error.message?.includes("Failed to fetch") || error.message?.includes("No internet")) {
        setConnectionStatus({
          isConnected: false,
          lastChecked: new Date().toISOString(),
        })
        // do NOT remove the token – let the user stay signed-in once back online
        return
      }

      // Any other error = assume token is bad
      removeAuthToken()
    }
  }

  const handleLogin = async () => {
    try {
      setLoading(true)
      const response = await apiCall("/auth/login", loginForm, "POST", false)

      if (response.status === "SUCCESS") {
        const { token, user } = response.data
        setAuthToken(token)
        setAuthState({
          isAuthenticated: true,
          user: user,
          token: token,
        })
        addNotification("Login successful!", "success")
      } else {
        addNotification(response.message || "Login failed", "error")
      }
    } catch (error: any) {
      console.error("Login error:", error)
      addNotification(`Login error: ${error.message}`, "error")
    } finally {
      setLoading(false)
    }
  }

  const handleSignup = async () => {
    try {
      // Validate passwords match
      if (signupForm.password !== signupForm.confirmPassword) {
        addNotification("Passwords do not match", "error")
        return
      }

      // Validate password strength
      if (signupForm.password.length < 8) {
        addNotification("Password must be at least 8 characters long", "error")
        return
      }

      setLoading(true)
      const response = await apiCall(
        "/auth/signup",
        {
          email: tokenEmail,
          password: signupForm.password,
          first_name: signupForm.first_name,
          last_name: signupForm.last_name,
          token: signupToken,
        },
        "POST",
        false,
      )

      if (response.status === "SUCCESS") {
        const { token, user } = response.data
        setAuthToken(token)
        setAuthState({
          isAuthenticated: true,
          user: user,
          token: token,
        })
        addNotification("Account created successfully! Welcome to QTEAM System.", "success")
        // Clear URL parameters
        window.history.replaceState({}, document.title, window.location.pathname)
      } else {
        addNotification(response.message || "Signup failed", "error")
      }
    } catch (error: any) {
      console.error("Signup error:", error)
      addNotification(`Signup error: ${error.message}`, "error")
    } finally {
      setLoading(false)
    }
  }

  const handleLogout = () => {
    removeAuthToken()
    setAuthState({
      isAuthenticated: false,
      user: null,
      token: null,
    })
    setActiveTab("dashboard")
    addNotification("Logged out successfully", "success")
  }

  const checkConnection = async () => {
    try {
      await apiCall("/health", null, "GET", false)
      setConnectionStatus({
        isConnected: true,
        lastChecked: new Date().toISOString(),
      })
    } catch (error) {
      console.error("Connection check failed:", error)
      setConnectionStatus({
        isConnected: false,
        lastChecked: new Date().toISOString(),
      })
    }
  }

  const loadInitialData = async () => {
    await Promise.all([loadUserRequests(), loadStatusData(), loadPendingRequests()])
  }

  const loadUserRequests = async () => {
    if (!authState.user) return

    try {
      setLoading(true)
      const response = await apiCall("/user/my-requests", null, "GET")

      if (response.status === "SUCCESS" && response.data?.requests) {
        setRequests(response.data.requests)
      }
    } catch (error: any) {
      console.error("Error loading user requests:", error)
      addNotification(`Error loading requests: ${error.message}`, "error")
    } finally {
      setLoading(false)
    }
  }

  const loadPendingRequests = async () => {
    if (authState.user?.role !== "admin") return

    try {
      const response = await apiCall("/check-status", {
        show_pending: true,
      })

      if (response.status === "SUCCESS" && response.data?.pending_requests) {
        setPendingRequests(response.data.pending_requests)
      }
    } catch (error: any) {
      console.error("Error loading pending requests:", error)
      addNotification(`Error loading pending requests: ${error.message}`, "error")
    }
  }

  const loadStatusData = async () => {
    try {
      const [activeResponse, pendingResponse] = await Promise.all([
        apiCall("/check-status", { show_active: true }),
        apiCall("/check-status", { show_pending: true }),
      ])

      const active = activeResponse.data?.active_resources?.length || 0
      const pending = pendingResponse.data?.pending_requests?.length || 0
      const urgent = pendingResponse.data?.urgent_requests?.length || 0

      setStatusData({
        active: activeResponse.data?.active_resources || [],
        pending: pendingResponse.data?.pending_requests || [],
        summary: { active, pending, urgent },
      })
    } catch (error: any) {
      console.error("Error loading status data:", error)
      addNotification(`Error loading status: ${error.message}`, "error")
    }
  }

  const submitRequest = async () => {
    try {
      setLoading(true)
      const response = await apiCall("/request-permissions", {
        email: requestForm.email,
        permissions: requestForm.permissions,
        duration_minutes: requestForm.duration_minutes,
        justification: requestForm.justification,
        urgency: requestForm.urgency,
        account_id: requestForm.account_id
      })

      if (response.status === "SUCCESS") {
        addNotification("Request submitted successfully! Administrators have been notified.", "success")
        setRequestForm({
          email: authState.user?.email || "",
          permissions: [],
          duration_minutes: 120,
          justification: "",
          urgency: "normal",
          account_id: ""
        })
        await loadUserRequests()
        await loadStatusData()
      } else {
        addNotification(response.message || "Error submitting request", "error")
      }
    } catch (error: any) {
      console.error("Error submitting request:", error)
      addNotification(`Error submitting request: ${error.message}`, "error")
    } finally {
      setLoading(false)
    }
  }

  const addNotification = (message: string, type: "success" | "error") => {
    const id = Date.now()
    setNotifications((prev) => [...prev, { id, message, type }])
    setTimeout(() => {
      setNotifications((prev) => prev.filter((n) => n.id !== id))
    }, 5000)
  }

  const renderContent = () => {
    if (authState.user?.role === "user") {
      switch (activeTab) {
        case "request":
          return (
            <RequestForm
              requestForm={requestForm}
              setRequestForm={setRequestForm}
              loading={loading}
              submitRequest={submitRequest}
              addNotification={addNotification}
              authState={authState}
              availableRoles={availableRoles}
            />
          )
        case "my-requests":
          return (
            <MyRequests
              requests={requests}
              loading={loading}
              loadUserRequests={loadUserRequests}
              authState={authState}
            />
          )
        default:
          return <Dashboard statusData={statusData} authState={authState} connectionStatus={connectionStatus} />
      }
    }

    if (authState.user?.role === "admin") {
      switch (activeTab) {
        case "admin":
          return (
            <AdminDashboard
              statusData={statusData}
              addNotification={addNotification}
              connectionStatus={connectionStatus}
            />
          )
        case "approvals":
          return (
            <Approvals
              pendingRequests={pendingRequests}
              loading={loading}
              loadPendingRequests={loadPendingRequests}
              authState={authState}
              addNotification={addNotification}
            />
          )
        case "invitations":
          return <UserInvitations addNotification={addNotification} />
        case "aws-accounts":  // ← ADD THIS CASE
          return <AWSAccountsManagement addNotification={addNotification} />
        default:
          return <Dashboard statusData={statusData} authState={authState} connectionStatus={connectionStatus} />
      }
    }

    return <Dashboard statusData={statusData} authState={authState} connectionStatus={connectionStatus} />
  }

  // Show token validation loading
  if (validatingToken) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 flex items-center justify-center px-4">
        <div className="max-w-md w-full bg-white rounded-2xl shadow-xl p-8 text-center">
          <div className="p-3 bg-blue-100 rounded-xl inline-block mb-4">
            <RefreshCw className="w-12 h-12 text-blue-600 animate-spin" />
          </div>
          <h1 className="text-2xl font-bold text-gray-900 mb-2">Validating Invitation</h1>
          <p className="text-gray-600">Please wait while we verify your signup token...</p>
        </div>
      </div>
    )
  }

  // Show token-based signup form
  if (signupToken && tokenEmail) {
    return (
      <div>
        <style>{`
          .animate-slide-in {
            animation: slideIn 0.3s ease-out;
          }
          
          @keyframes slideIn {
            from {
              transform: translateX(100%);
              opacity: 0;
            }
            to {
              transform: translateX(0);
              opacity: 1;
            }
          }
        `}</style>

        <Notifications notifications={notifications} />
        <TokenSignupForm
          signupForm={signupForm}
          setSignupForm={setSignupForm}
          loading={loading}
          handleSignup={handleSignup}
          tokenEmail={tokenEmail}
        />
      </div>
    )
  }

  // Show login form if not authenticated
  if (!authState.isAuthenticated) {
    return (
      <div>
        <style>{`
          .animate-slide-in {
            animation: slideIn 0.3s ease-out;
          }
          
          @keyframes slideIn {
            from {
              transform: translateX(100%);
              opacity: 0;
            }
            to {
              transform: translateX(0);
              opacity: 1;
            }
          }
        `}</style>

        <Notifications notifications={notifications} />
        <LoginForm loginForm={loginForm} setLoginForm={setLoginForm} loading={loading} handleLogin={handleLogin} />
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-gray-50">
      <style>{`
        .animate-slide-in {
          animation: slideIn 0.3s ease-out;
        }
        
        @keyframes slideIn {
          from {
            transform: translateX(100%);
            opacity: 0;
          }
          to {
            transform: translateX(0);
            opacity: 1;
          }
        }
      `}</style>

      <Notifications notifications={notifications} />

      <Header
        authState={authState}
        statusData={statusData}
        connectionStatus={connectionStatus}
        handleLogout={handleLogout}
        availableRoles={availableRoles}
      />

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <Navigation activeTab={activeTab} setActiveTab={setActiveTab} authState={authState} statusData={statusData} />

        {loading && (
          <div className="mb-6 p-4 bg-blue-50 rounded-xl border border-blue-200">
            <div className="flex items-center">
              <RefreshCw className="animate-spin h-5 w-5 text-blue-600 mr-3" />
              <span className="text-blue-800 font-medium">Loading...</span>
            </div>
          </div>
        )}

        {renderContent()}
      </main>
    </div>
  )
}

export default TEAMSystem
