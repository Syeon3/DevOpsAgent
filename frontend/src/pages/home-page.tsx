import type { UserInfo } from "@/types"
import { UserCard } from "@/components/user/user-card"
// 微信扫码登录暂不在界面上展示；恢复时同时取消下面导入和 JSX 区块的注释
// import { WeixinQRCode } from "@/channels/weixin/WeixinQRCode"

const USERS: UserInfo[] = [
  { id: "00000000-0000-0000-0000-000000000001", name: "Jack", gender: "male" },
  { id: "00000000-0000-0000-0000-000000000002", name: "Rose", gender: "female" },
]

type HomePageProps = {
  onSelectUser: (user: UserInfo) => void
}

export function HomePage({ onSelectUser }: HomePageProps) {
  return (
    <div className="flex min-h-screen items-center justify-center gap-12 bg-background p-8">
      {/* Left: User selection */}
      <div className="flex gap-8">
        {USERS.map((user) => (
          <UserCard key={user.id} user={user} onClick={() => onSelectUser(user)} />
        ))}
      </div>

      {/* 微信扫码登录暂不在界面上展示（后端 WebSocket 与组件代码均保留） */}
      {/*
      <div className="flex flex-col items-center">
        <p className="text-sm text-muted-foreground mb-3">或使用微信扫码登录</p>
        <WeixinQRCode />
      </div>
      */}
    </div>
  )
}