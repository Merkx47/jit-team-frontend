"use client"

import type React from "react"
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
  Activity,
  BarChart3,
  ChevronDown,
  ChevronUp,
  RefreshCw,
  Calendar,
  FileText,
  UserCheck,
  Zap,
  Timer,
  LogOut,
  LogIn,
  Mail,
  UserPlus,
  Copy,
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
  role: string
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

interface RequestForm {
  email: string
  permissions: string[]
  duration_minutes: number
  justification: string
  urgency: string
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

interface NavItem {
  id: string
  label: string
  icon: any
  badge?: number
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
      config.body = JSON.stringify(data)
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
      }

      throw new Error(errorData.message || errorData.detail || `Request failed with status ${response.status}`)
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

    throw error
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

// Login Component (No Signup Toggle)
const LoginForm: React.FC<{
  loginForm: LoginForm
  setLoginForm: React.Dispatch<React.SetStateAction<LoginForm>>
  loading: boolean
  handleLogin: () => void
}> = ({ loginForm, setLoginForm, loading, handleLogin }) => {
  const handleLoginSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    handleLogin()
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 flex items-center justify-center px-4">
      <div className="max-w-md w-full bg-white rounded-2xl shadow-xl p-8">
        <div className="text-center mb-8">
          <div className="p-3 bg-blue-100 rounded-xl inline-block mb-4">
            <Shield className="w-12 h-12 text-blue-600" />
          </div>
          <h1 className="text-3xl font-bold bg-gradient-to-r from-blue-600 to-purple-600 bg-clip-text text-transparent">
            QTEAM System
          </h1>
          <p className="text-gray-600 mt-2">Temporary Elevated Access Management</p>
        </div>

        <form onSubmit={handleLoginSubmit} className="space-y-6">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Email Address</label>
            <input
              type="email"
              value={loginForm.email}
              onChange={(e) => setLoginForm((prev) => ({ ...prev, email: e.target.value }))}
              placeholder="Enter your email"
              className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              required
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Password</label>
            <input
              type="password"
              value={loginForm.password}
              onChange={(e) => setLoginForm((prev) => ({ ...prev, password: e.target.value }))}
              placeholder="Enter your password"
              className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              required
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full bg-blue-600 text-white py-3 px-4 rounded-lg font-medium hover:bg-blue-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center space-x-2"
          >
            {loading ? (
              <>
                <RefreshCw className="w-4 h-4 animate-spin" />
                <span>Signing in...</span>
              </>
            ) : (
              <>
                <LogIn className="w-4 h-4" />
                <span>Sign In</span>
              </>
            )}
          </button>
        </form>

        <div className="mt-6 p-4 bg-blue-50 rounded-lg">
          <p className="text-sm text-blue-800 font-medium mb-2">Demo Credentials:</p>
          <div className="text-xs text-blue-700 space-y-1">
            <div>Admin: admin@company.com / password123</div>
            <div>User: user@company.com / password123</div>
          </div>
        </div>

        <div className="mt-4 text-center">
          <p className="text-sm text-gray-600">Need an account? Contact your administrator for an invitation.</p>
        </div>
      </div>
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
  const handleSignupSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    handleSignup()
  }

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
              <label className="block text-sm font-medium text-gray-700 mb-2">First Name</label>
              <input
                type="text"
                value={signupForm.first_name}
                onChange={(e) => setSignupForm((prev) => ({ ...prev, first_name: e.target.value }))}
                placeholder="First name"
                className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-green-500 focus:border-green-500"
                required
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Last Name</label>
              <input
                type="text"
                value={signupForm.last_name}
                onChange={(e) => setSignupForm((prev) => ({ ...prev, last_name: e.target.value }))}
                placeholder="Last name"
                className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-green-500 focus:border-green-500"
                required
              />
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
            <label className="block text-sm font-medium text-gray-700 mb-2">Password</label>
            <input
              type="password"
              value={signupForm.password}
              onChange={(e) => setSignupForm((prev) => ({ ...prev, password: e.target.value }))}
              placeholder="Create a secure password (min 8 characters)"
              className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-green-500 focus:border-green-500"
              required
              minLength={8}
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Confirm Password</label>
            <input
              type="password"
              value={signupForm.confirmPassword}
              onChange={(e) => setSignupForm((prev) => ({ ...prev, confirmPassword: e.target.value }))}
              placeholder="Confirm your password"
              className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-green-500 focus:border-green-500"
              required
            />
          </div>

          <button
            type="submit"
            disabled={loading}
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
}> = ({ authState, statusData, connectionStatus, handleLogout }) => (
  <header className="bg-white shadow-sm border-b border-gray-200">
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
      <div className="flex items-center justify-between h-20">
        <div className="flex items-center">
          <div className="p-2 bg-blue-100 rounded-xl mr-4">
            <Shield className="w-10 h-10 text-blue-600" />
          </div>
          <div>
            <h1 className="text-2xl font-bold bg-gradient-to-r from-blue-600 to-purple-600 bg-clip-text text-transparent">
              QTEAM
            </h1>
            <p className="text-sm text-gray-500 font-medium">Qucoon Temporary Elevated Access Management</p>
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
              {authState.user?.role.toUpperCase()}
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
          <button
            onClick={handleLogout}
            className="flex items-center space-x-2 text-gray-600 hover:text-gray-800 px-3 py-2 rounded-lg hover:bg-gray-100 transition-colors"
          >
            <LogOut className="w-4 h-4" />
            <span className="text-sm font-medium">Logout</span>
          </button>
        </div>
      </div>
    </div>
  </header>
)

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

    if (authState.user?.role === "admin") {
      return [
        ...baseItems,
        { id: "admin", label: "Administration", icon: Settings },
        { id: "approvals", label: "All Requests", icon: Users, badge: statusData.summary.pending },
        { id: "invitations", label: "User Invitations", icon: Mail },
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
            <CheckCircle className="w-5 h-5 mr-3 mt-0.5 text-green-600" />
          ) : (
            <XCircle className="w-5 h-5 mr-3 mt-0.5 text-red-600" />
          )}
          <div className="text-sm leading-relaxed">{notification.message}</div>
        </div>
      </div>
    ))}
  </div>
)

// User Invitations Component
const UserInvitations: React.FC<{
  addNotification: (message: string, type: "success" | "error") => void
}> = ({ addNotification }) => {
  const [inviteEmail, setInviteEmail] = useState("")
  const [inviteRole, setInviteRole] = useState("user")
  const [loading, setLoading] = useState(false)
  const [generatedLink, setGeneratedLink] = useState("")

  const handleSendInvitation = async () => {
    if (!inviteEmail) {
      addNotification("Please enter an email address", "error")
      return
    }

    try {
      setLoading(true)
      const response = await apiCall("/auth/generate-signup-link", {
        email: inviteEmail,
        role: inviteRole,
      })

      if (response.status === "SUCCESS") {
        // The backend returns signup_link, so use that
        const signupLink = response.data.signup_link
        setGeneratedLink(signupLink)
        addNotification("Invitation created successfully!", "success")
        setInviteEmail("")
      } else {
        addNotification(response.message || "Failed to create invitation", "error")
      }
    } catch (error: any) {
      console.error("Error creating invitation:", error)
      addNotification(`Error: ${error.message}`, "error")
    } finally {
      setLoading(false)
    }
  }

  const copyToClipboard = async () => {
    try {
      await navigator.clipboard.writeText(generatedLink)
      addNotification("Invitation link copied to clipboard!", "success")
    } catch (error) {
      addNotification("Failed to copy link", "error")
    }
  }

  return (
    <div className="space-y-6">
      <div className="bg-white rounded-xl shadow-sm border border-gray-200">
        <div className="p-6 border-b border-gray-100">
          <h3 className="text-xl font-semibold text-gray-900 flex items-center">
            <Mail className="w-6 h-6 mr-3 text-blue-600" />
            Send User Invitation
          </h3>
          <p className="text-gray-600 mt-1">Create signup tokens and invite new users to the QTEAM system</p>
        </div>

        <div className="p-6 space-y-6">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Email Address *</label>
            <input
              type="email"
              value={inviteEmail}
              onChange={(e) => setInviteEmail(e.target.value)}
              placeholder="Enter user's email address"
              className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              required
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">User Role</label>
            <select
              value={inviteRole}
              onChange={(e) => setInviteRole(e.target.value)}
              className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            >
              <option value="user">User - Can request access</option>
              <option value="admin">Admin - Can approve requests and manage users</option>
            </select>
          </div>

          <button
            onClick={handleSendInvitation}
            disabled={loading || !inviteEmail}
            className="bg-blue-600 text-white py-3 px-6 rounded-lg font-medium disabled:bg-gray-300 disabled:cursor-not-allowed hover:bg-blue-700 transition-all duration-200 flex items-center space-x-2"
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
            <div className="mt-6 p-4 bg-green-50 rounded-lg border border-green-200">
              <h4 className="font-medium text-green-900 mb-2">Invitation Created!</h4>
              <p className="text-sm text-green-700 mb-3">
                Share this link with the user to complete their registration:
              </p>
              <div className="flex items-center space-x-2">
                <input
                  type="text"
                  value={generatedLink}
                  readOnly
                  className="flex-1 px-3 py-2 text-sm border border-green-300 rounded bg-white"
                />
                <button
                  onClick={copyToClipboard}
                  className="px-3 py-2 bg-green-600 text-white rounded hover:bg-green-700 transition-colors flex items-center space-x-1"
                >
                  <Copy className="w-4 h-4" />
                  <span className="text-sm">Copy</span>
                </button>
              </div>
              <p className="text-xs text-green-600 mt-2">
                💡 Send this link via email or your preferred communication method
              </p>
            </div>
          )}
        </div>
      </div>

      <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
        <h4 className="text-lg font-semibold text-gray-900 mb-4">How User Invitations Work</h4>
        <div className="space-y-3 text-sm text-gray-600">
          <div className="flex items-start space-x-3">
            <div className="w-6 h-6 bg-blue-100 rounded-full flex items-center justify-center flex-shrink-0 mt-0.5">
              <span className="text-blue-600 font-semibold text-xs">1</span>
            </div>
            <div>
              <strong>Create Invitation:</strong> Enter the user's email and select their role to generate a secure
              signup token.
            </div>
          </div>
          <div className="flex items-start space-x-3">
            <div className="w-6 h-6 bg-blue-100 rounded-full flex items-center justify-center flex-shrink-0 mt-0.5">
              <span className="text-blue-600 font-semibold text-xs">2</span>
            </div>
            <div>
              <strong>Share Link:</strong> Send the generated invitation link to the user via email or secure
              communication.
            </div>
          </div>
          <div className="flex items-start space-x-3">
            <div className="w-6 h-6 bg-blue-100 rounded-full flex items-center justify-center flex-shrink-0 mt-0.5">
              <span className="text-blue-600 font-semibold text-xs">3</span>
            </div>
            <div>
              <strong>User Registration:</strong> The user clicks the link and completes their account setup with their
              name and password.
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
  authState: AuthState
}> = ({ requestForm, setRequestForm, loading, submitRequest, addNotification, authState }) => {
  const justificationRef = useRef<HTMLTextAreaElement>(null)
  const [expandedCategories, setExpandedCategories] = useState<{ [key: string]: boolean }>({})

  const groupedPermissions = PERMISSIONS.reduce((acc: { [key: string]: Permission[] }, perm) => {
    if (!acc[perm.category]) {
      acc[perm.category] = []
    }
    acc[perm.category].push(perm)
    return acc
  }, {})

  const handleSubmit = () => {
    if (!requestForm.email) {
      addNotification("Please enter your email address", "error")
      return
    }
    if (requestForm.permissions.length === 0) {
      addNotification("Please select at least one permission", "error")
      return
    }
    if (requestForm.justification.length < 10) {
      addNotification("Justification must be at least 10 characters", "error")
      if (justificationRef.current) {
        justificationRef.current.focus()
      }
      return
    }

    submitRequest()
  }

  return (
    <div className="space-y-6">
      <div className="bg-white rounded-xl shadow-sm border border-gray-200">
        <div className="p-6 border-b border-gray-100">
          <h3 className="text-xl font-semibold text-gray-900 flex items-center">
            <Plus className="w-6 h-6 mr-3 text-blue-600" />
            Request Temporary Access
          </h3>
          <p className="text-gray-600 mt-1">Request elevated permissions for AWS resources with automatic expiration</p>
        </div>

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
                })
              }
              className="px-4 py-2 text-gray-600 hover:text-gray-800 transition-colors"
            >
              Reset Form
            </button>
            <button
              onClick={handleSubmit}
              disabled={
                loading ||
                !requestForm.email ||
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

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <h3 className="text-xl font-semibold text-gray-900 flex items-center">
          <Eye className="w-6 h-6 mr-3 text-blue-600" />
          My Access Requests
        </h3>
        <div className="flex items-center space-x-3">
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

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
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
                      User: {request.user_name} | Role: {request.role_name}
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

// Approvals Component
const Approvals: React.FC<{
  pendingRequests: any[]
  loading: boolean
  loadPendingRequests: () => void
  authState: AuthState
  addNotification: (message: string, type: "success" | "error") => void
}> = ({ pendingRequests, loading, loadPendingRequests, authState, addNotification }) => {
  const [processingId, setProcessingId] = useState<string | null>(null)
  const [commentModal, setCommentModal] = useState<{ show: boolean; requestId: string | null; action: string | null }>({
    show: false,
    requestId: null,
    action: null,
  })
  const [comment, setComment] = useState("")

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
        addNotification(`Request ${action.toLowerCase()}d successfully`, "success")
        await loadPendingRequests()
      } else {
        addNotification(response.message || "Failed to process request", "error")
      }
    } catch (error: any) {
      console.error("Error processing approval:", error)
      addNotification(`Error: ${error.message}`, "error")
    } finally {
      setProcessingId(null)
      setCommentModal({ show: false, requestId: null, action: null })
      setComment("")
    }
  }

  const openCommentModal = (requestId: string, action: string) => {
    setCommentModal({ show: true, requestId, action })
    setComment("")
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h3 className="text-xl font-semibold text-gray-900 flex items-center">
          <Clock className="w-6 h-6 mr-3 text-blue-600" />
          Pending Approvals
        </h3>
        <button
          onClick={loadPendingRequests}
          disabled={loading}
          className="text-blue-600 hover:text-blue-800 flex items-center text-sm font-medium px-3 py-2 rounded-lg hover:bg-blue-50 transition-colors disabled:opacity-50"
        >
          <RefreshCw className={`w-4 h-4 mr-1 ${loading ? "animate-spin" : ""}`} />
          Refresh
        </button>
      </div>

      {pendingRequests.length === 0 ? (
        <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-12 text-center">
          <div className="w-16 h-16 bg-gray-100 rounded-full flex items-center justify-center mx-auto mb-4">
            <Clock className="w-8 h-8 text-gray-400" />
          </div>
          <div className="text-gray-500 text-lg mb-2">No pending requests</div>
          <div className="text-gray-400 text-sm">All requests have been processed</div>
        </div>
      ) : (
        <div className="space-y-4">
          {pendingRequests.map((request) => (
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
                    <span className="text-xs text-gray-500">
                      Requested by: <strong>{request.email}</strong>
                    </span>
                  </div>
                  <div className="text-xs text-gray-500">
                    {request.pending_for_hours && `Pending for ${request.pending_for_hours}h`}
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
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
                    <div className="text-sm font-medium text-gray-900 mb-2">Duration</div>
                    <div className="text-sm text-gray-600">
                      {request.duration_minutes} minutes ({(request.duration_minutes / 60).toFixed(1)} hours)
                    </div>
                  </div>
                </div>

                {request.justification && (
                  <div className="bg-gray-50 rounded-lg p-4 mb-4">
                    <div className="text-sm font-medium text-gray-900 mb-1">Business Justification</div>
                    <div className="text-sm text-gray-700">{request.justification}</div>
                  </div>
                )}

                <div className="flex items-center justify-end space-x-3 pt-4 border-t border-gray-100">
                  <button
                    onClick={() => openCommentModal(request.request_id, "DENIED")}
                    disabled={processingId === request.request_id}
                    className="px-4 py-2 text-red-600 border border-red-300 rounded-lg hover:bg-red-50 transition-colors font-medium disabled:opacity-50"
                  >
                    Deny
                  </button>
                  <button
                    onClick={() => handleApproval(request.request_id, "APPROVED")}
                    disabled={processingId === request.request_id}
                    className="px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 transition-colors font-medium disabled:opacity-50 flex items-center space-x-2"
                  >
                    {processingId === request.request_id ? (
                      <>
                        <RefreshCw className="w-4 h-4 animate-spin" />
                        <span>Processing...</span>
                      </>
                    ) : (
                      <>
                        <CheckCircle className="w-4 h-4" />
                        <span>Approve</span>
                      </>
                    )}
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Comment Modal */}
      {commentModal.show && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-xl p-6 max-w-md w-full mx-4">
            <h3 className="text-lg font-semibold text-gray-900 mb-4">
              {commentModal.action === "DENIED" ? "Deny Request" : "Approve Request"}
            </h3>
            <div className="mb-4">
              <label className="block text-sm font-medium text-gray-700 mb-2">
                {commentModal.action === "DENIED" ? "Reason for denial:" : "Comments (optional):"}
              </label>
              <textarea
                value={comment}
                onChange={(e) => setComment(e.target.value)}
                placeholder={
                  commentModal.action === "DENIED" ? "Please provide a reason for denial..." : "Add any comments..."
                }
                rows={3}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              />
            </div>
            <div className="flex items-center justify-end space-x-3">
              <button
                onClick={() => setCommentModal({ show: false, requestId: null, action: null })}
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
                className={`px-4 py-2 rounded-lg font-medium transition-colors disabled:opacity-50 ${
                  commentModal.action === "DENIED"
                    ? "bg-red-600 text-white hover:bg-red-700"
                    : "bg-green-600 text-white hover:bg-green-700"
                }`}
              >
                {commentModal.action === "DENIED" ? "Deny Request" : "Approve Request"}
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
      })

      if (response.status === "SUCCESS") {
        addNotification("Request submitted successfully! Administrators have been notified.", "success")
        setRequestForm({
          email: authState.user?.email || "",
          permissions: [],
          duration_minutes: 120,
          justification: "",
          urgency: "normal",
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
