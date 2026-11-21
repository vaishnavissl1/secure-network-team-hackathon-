import type { Metadata } from "next";
import "./globals.css";
export const metadata: Metadata = { title: "Shield Wall • Edge observatory", description: "Evidence from the PS6 Shield Wall application security lab." };
export default function Root({children}:{children:React.ReactNode}) {
  return <html lang="en"><body>{children}</body></html>;
}
