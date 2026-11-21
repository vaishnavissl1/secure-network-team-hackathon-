import { Shield } from "lucide-react";

export default function Layout({children}:{children:React.ReactNode}) {
  return <><header><nav aria-label="Main navigation"><a className="brand" href="/"><Shield aria-hidden size={24}/>Shield Wall</a><div className="links"><a href="/">Overview</a><a href="/controls/">Controls</a><a href="/activity/">Live activity</a><a href="/evidence/">Evidence</a><a href="/demo/">Demo guide</a></div></nav></header>{children}<footer><span>Shield Wall</span><span>23CSE336 · Secure Networks Hackathon</span></footer></>;
}
