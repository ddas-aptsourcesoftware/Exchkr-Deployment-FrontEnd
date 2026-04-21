import axios from "axios";
import { useAuthStore } from "../stores/authStore";

/* ---------------------------------------
   Cookie helpers
---------------------------------------- */
const getCookie = (name) => {
  if (typeof document === "undefined") return null;
  const match = document.cookie.match(new RegExp("(^| )" + name + "=([^;]+)"));
  return match ? decodeURIComponent(match[2]) : null;
};

/* ---------------------------------------
   Axios instance
---------------------------------------- */
const axiosClient = axios.create({
  baseURL: process.env.NEXT_PUBLIC_API_BASE_URL,
  withCredentials: true,
});

/* ---------------------------------------
   Refresh Token Handling
---------------------------------------- */
let isRefreshing = false;
let failedQueue = [];

const processQueue = (error) => {
  failedQueue.forEach(({ resolve, reject }) => {
    if (error) reject(error);
    else resolve();
  });
  failedQueue = [];
};

const AUTH_EXCLUDED_PATHS = [
  "/auth/login",
  "/auth/refresh-token",
  "/api/admin/onboarding/club",
  "/api/password/reset",
];

/* ---------------------------------------
   Request Interceptor
---------------------------------------- */
axiosClient.interceptors.request.use(
  (config) => {
    if (typeof document === "undefined") return config;

    const method = config.method?.toUpperCase();
    const unsafeMethods = ["POST", "PUT", "PATCH", "DELETE"];

    // Skip auth endpoints
    if (AUTH_EXCLUDED_PATHS.some((p) => config.url?.includes(p))) {
      return config;
    }

    // Attach Access Token
    const accessToken = getCookie("frontendAccessToken");
    if (accessToken) {
      config.headers["Authorization"] = `Bearer ${accessToken}`;
    }

    return config;
  },
  (error) => Promise.reject(error)
);

/* ---------------------------------------
   Response Interceptor
---------------------------------------- */
axiosClient.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;

    if (!error.response || !originalRequest) {
      return Promise.reject(error);
    }

    const requestUrl = originalRequest.url || "";
    const isAuthEndpoint = AUTH_EXCLUDED_PATHS.some((p) =>
      requestUrl.includes(p)
    );

    // NEVER retry refresh on auth endpoints
    if (isAuthEndpoint) {
      return Promise.reject(error);
    }

    /* ---- 401 refresh flow ---- */
    if (error.response.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;

      if (isRefreshing) {
        return new Promise((resolve, reject) => {
          failedQueue.push({ resolve, reject });
        }).then(() => axiosClient(originalRequest));
      }

      isRefreshing = true;

      try {
        const refreshToken = getCookie("refreshToken");

        await axios.post(
          `${process.env.NEXT_PUBLIC_API_BASE_URL}/auth/refresh-token`,
          {},
          {
            withCredentials: true,
            headers: refreshToken
              ? { Authorization: `Bearer ${refreshToken}` }
              : {},
          }
        );

        processQueue(null);

        return axiosClient(originalRequest);
      } catch (e) {
        processQueue(e);
        useAuthStore.getState().clearUser();
        if (typeof window !== "undefined") window.location.href = "/login";
        return Promise.reject(e);
      } finally {
        isRefreshing = false;
      }
    }

    return Promise.reject(error);
  }
);

export default axiosClient;