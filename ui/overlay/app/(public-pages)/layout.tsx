import { Shield } from "lucide-react";
import Link from "next/link";
export default function Layout({children}:{children:React.ReactNode}) {
  return <><header><nav aria-label="Main navigation"><Link className="brand" href="/"><Shield aria-hidden size={24}/>Shield Wall</Link><div className="links"><Link href="/">Overview</Link><Link href="/controls/">Controls</Link><Link href="/evidence/">Evidence</Link><Link href="/demo/">Demo guide</Link></div></nav></header>{children}<footer><span>Shield Wall</span><span>23CSE336 · Secure Networks Hackathon</span></footer></>;
}
