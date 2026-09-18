import { useState } from 'react'
import Scanner from './components/Scanner'
import Results from './components/Results'
import History from './components/History'

const TABS = [
  { id: 'scanner', label: '🎯 New Scan' },
  { id: 'results', label: '📊 Results' },
  { id: 'history', label: '🕓 History' },
]

function App() {
  const [tab, setTab] = useState('scanner')
  const [scanId, setScanId] = useState(null)

  const handleScanStart = (id) => {
    setScanId(id)
    setTab('results')
  }

  const handleSelectHistory = (id) => {
    setScanId(id)
    setTab('results')
  }

  return (
    <div style={{ minHeight: '100vh', background: '#0f1117' }}>
      <header
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '1.2rem 2rem',
          borderBottom: '1px solid #1e293b',
          flexWrap: 'wrap',
          gap: '1rem',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
          <span style={{ fontSize: '1.4rem' }}>🗡️</span>
          <span style={{ fontWeight: 800, fontSize: '1.2rem', letterSpacing: '0.02em', color: '#e2e8f0' }}>
            GreyLance
          </span>
          <span
            style={{
              fontSize: '0.7rem',
              color: '#64748b',
              border: '1px solid #334155',
              borderRadius: '999px',
              padding: '0.15rem 0.6rem',
            }}
          >
            authorized use only
          </span>
        </div>
        <nav style={{ display: 'flex', gap: '0.4rem' }}>
          {TABS.map((t) => (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              style={{
                padding: '0.5rem 1rem',
                borderRadius: '8px',
                border: 'none',
                cursor: 'pointer',
                background: tab === t.id ? '#38bdf8' : 'transparent',
                color: tab === t.id ? '#0f1117' : '#94a3b8',
                fontWeight: 600,
                fontSize: '0.85rem',
                transition: 'all 0.15s',
              }}
            >
              {t.label}
            </button>
          ))}
        </nav>
      </header>

      <main style={{ padding: '2rem', maxWidth: '1100px', margin: '0 auto' }}>
        {tab === 'scanner' && <Scanner onScanStart={handleScanStart} />}
        {tab === 'results' && <Results scanId={scanId} />}
        {tab === 'history' && <History onSelect={handleSelectHistory} />}
      </main>
    </div>
  )
}

export default App
