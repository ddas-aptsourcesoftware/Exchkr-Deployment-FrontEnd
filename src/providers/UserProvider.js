"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { useAuthStore } from "@/stores/authStore";
import axiosClient from "@/services/axiosClient";

export default function UserProvider({ children }) {
  const router = useRouter();
  const setUser = useAuthStore((s) => s.setUser);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchUser = async () => {
      try {
        const res = await axiosClient.get("/api/user-data");

        if (res.status === 200 && res.data) {
          setUser(res.data);
        }
      } catch (err) {
        if (err.response?.status === 401) {
          setUser(null);
          router.replace("/login");
        } else {
          console.error("User fetch failed (network / cold start)");
        }
      } finally {
        setLoading(false);
      }
    };

    fetchUser();
  }, [setUser, router]);

  if (loading) return null;

  return children;
}
