"use client";
import { useEffect } from "react";
import { getBasePath } from "@/lib/basepath";

export default function Home() {
  useEffect(() => {
    const base = getBasePath();
    const token = localStorage.getItem("token");
    if (token) {
      window.location.href = base + "/dashboard";
    } else {
      window.location.href = base + "/login";
    }
  }, []);

  return (
    <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100vh" }}>
      <div className="status-dot starting" style={{ width: 20, height: 20 }} />
    </div>
  );
}
