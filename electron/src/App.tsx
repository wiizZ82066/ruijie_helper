import { useState } from 'react';
import Sidebar from './components/Sidebar';
import HotspotPage from './components/HotspotPage';
import NetworkPage from './components/NetworkPage';

type PageId = 'hotspot' | 'network';

function App() {
  const [currentPage, setCurrentPage] = useState<PageId>('hotspot');

  return (
    <div className="app">
      <Sidebar currentPage={currentPage} onNavigate={setCurrentPage} />
      <main className="main-content">
        {currentPage === 'hotspot' ? <HotspotPage /> : <NetworkPage />}
      </main>
    </div>
  );
}

export default App;
