import axios from "axios";

/* ---------------------------------------
   Cookie helper
---------------------------------------- */
const getCookie = (name) => {
  if (typeof document === "undefined") return null;

  const match = document.cookie.match(
    new RegExp("(^| )" + name + "=([^;]+)")
  );

  return match ? decodeURIComponent(match[2]) : null;
};

/* ---------------------------------------
   Token sanitizer — strips accidental "Bearer " prefix
---------------------------------------- */
const sanitizeToken = (token) => {
  if (!token) return null;
  const stripped = token.startsWith("Bearer ") ? token.slice(7) : token;
  return stripped.trim();
};

/* ---------------------------------------
   Cookie setter — always stores raw token
---------------------------------------- */
const setAuthCookies = (accessToken, refreshToken) => {
  const rawAccess = sanitizeToken(accessToken);
  const rawRefresh = sanitizeToken(refreshToken);

  if (rawAccess) {
    document.cookie = `accessToken=${rawAccess}; path=/; SameSite=Strict`;
  }
  if (rawRefresh) {
    document.cookie = `refreshToken=${rawRefresh}; path=/; SameSite=Strict`;
  }
};

const clearAuthCookies = () => {
  document.cookie =
    "accessToken=; path=/; expires=Thu, 01 Jan 1970 00:00:00 UTC; SameSite=Strict";
  document.cookie =
    "refreshToken=; path=/; expires=Thu, 01 Jan 1970 00:00:00 UTC; SameSite=Strict";
};

/* ---------------------------------------
   Axios instance
---------------------------------------- */
const axiosClient = axios.create({
  baseURL: process.env.NEXT_PUBLIC_API_BASE_URL,
  withCredentials: true,
});

/* ---------------------------------------
   Refresh handling
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
    const raw = getCookie("accessToken");
    const accessToken = sanitizeToken(raw);

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

    if (isAuthEndpoint) {
      return Promise.reject(error);
    }

    /* ---- 401 REFRESH FLOW ---- */
    if (error.response.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;

      if (isRefreshing) {
        return new Promise((resolve, reject) => {
          failedQueue.push({ resolve, reject });
        }).then(() => axiosClient(originalRequest));
      }

      isRefreshing = true;

      try {
        const raw = getCookie("refreshToken");
        const refreshToken = sanitizeToken(raw);

        const { data } = await axios.post(
          `${process.env.NEXT_PUBLIC_API_BASE_URL}/auth/refresh-token`,
          {},
          {
            withCredentials: true,
            headers: refreshToken
              ? { Authorization: `Bearer ${refreshToken}` }
              : {},
          }
        );

        setAuthCookies(data.accessToken, data.refreshToken);

        processQueue(null);

        return axiosClient(originalRequest);
      } catch (e) {
        processQueue(e);
        clearAuthCookies();

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