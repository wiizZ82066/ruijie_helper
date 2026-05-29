interface SidebarProps {
  currentPage: string;
  onNavigate: (page: 'hotspot' | 'network') => void;
}

const navItems = [
  { id: 'hotspot' as const, icon: '🔥', label: '热点管理' },
  { id: 'network' as const, icon: '🖧', label: '网卡控制' },
];

export default function Sidebar({ currentPage, onNavigate }: SidebarProps) {
  return (
    <aside className="sidebar">
      <div className="sidebar-title">校园网认证助手</div>
      <div className="sidebar-sep" />
      <nav className="sidebar-nav">
        {navItems.map((item) => (
          <div
            key={item.id}
            className={`sidebar-item${currentPage === item.id ? ' active' : ''}`}
            onClick={() => onNavigate(item.id)}
          >
            <span className="sidebar-item-icon">{item.icon}</span>
            <span>{item.label}</span>
          </div>
        ))}
      </nav>
      <div className="sidebar-version">v3.0.0</div>
    </aside>
  );
}
