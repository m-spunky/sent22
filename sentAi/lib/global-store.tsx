"use client"

import React, { createContext, useContext, useState, useEffect } from "react"

interface GlobalStore {
  visualSandboxEnabled: boolean
  setVisualSandboxEnabled: (v: boolean) => void
}

const GlobalStoreContext = createContext<GlobalStore>({
  visualSandboxEnabled: false,
  setVisualSandboxEnabled: () => {},
})

export function GlobalStoreProvider({ children }: { children: React.ReactNode }) {
  const [visualSandboxEnabled, setVisualSandboxEnabled] = useState(false)

  useEffect(() => {
    try {
      const stored = localStorage.getItem("sentinel_visual_sandbox")
      if (stored === "true") setVisualSandboxEnabled(true)
    } catch {}
  }, [])

  const setAndPersist = (v: boolean) => {
    setVisualSandboxEnabled(v)
    try { localStorage.setItem("sentinel_visual_sandbox", String(v)) } catch {}
  }

  return (
    <GlobalStoreContext.Provider value={{ visualSandboxEnabled, setVisualSandboxEnabled: setAndPersist }}>
      {children}
    </GlobalStoreContext.Provider>
  )
}

export function useGlobalStore() {
  return useContext(GlobalStoreContext)
}
