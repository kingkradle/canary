import React, { useState, useEffect } from 'react';
import { Search, X, ExternalLink, ChevronDown, ChevronUp } from 'lucide-react';

const MitreAttackMatrix = () => {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [selectedTechnique, setSelectedTechnique] = useState(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [expandedTactics, setExpandedTactics] = useState({});

  // Tactics in order as they appear in the MITRE ATT&CK matrix
  const tacticOrder = [
    'reconnaissance',
    'resource-development',
    'initial-access',
    'execution',
    'persistence',
    'privilege-escalation',
    'defense-evasion',
    'credential-access',
    'discovery',
    'lateral-movement',
    'collection',
    'command-and-control',
    'exfiltration',
    'impact'
  ];

  const tacticNames = {
    'reconnaissance': 'Reconnaissance',
    'resource-development': 'Resource Development',
    'initial-access': 'Initial Access',
    'execution': 'Execution',
    'persistence': 'Persistence',
    'privilege-escalation': 'Privilege Escalation',
    'defense-evasion': 'Defense Evasion',
    'credential-access': 'Credential Access',
    'discovery': 'Discovery',
    'lateral-movement': 'Lateral Movement',
    'collection': 'Collection',
    'command-and-control': 'Command and Control',
    'exfiltration': 'Exfiltration',
    'impact': 'Impact'
  };

  useEffect(() => {
    fetchMitreData();
  }, []);

  const fetchMitreData = async () => {
    try {
      const response = await fetch(
        'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json'
      );
      const json = await response.json();
      
      // Parse the data
      const techniques = {};
      const tactics = {};
      
      json.objects.forEach(obj => {
        // Get tactics
        if (obj.type === 'x-mitre-tactic') {
          const tacticId = obj.x_mitre_shortname;
          tactics[tacticId] = {
            id: tacticId,
            name: obj.name,
            description: obj.description
          };
        }
        
        // Get techniques (excluding sub-techniques)
        if (obj.type === 'attack-pattern' && !obj.revoked && !obj.x_mitre_deprecated) {
          const externalRefs = obj.external_references || [];
          const mitreRef = externalRefs.find(ref => ref.source_name === 'mitre-attack');
          
          if (mitreRef && mitreRef.external_id) {
            // Skip sub-techniques (they have a dot in the ID)
            if (mitreRef.external_id.includes('.')) {
              return;
            }
            
            const killChainPhases = obj.kill_chain_phases || [];
            const mitreTactics = killChainPhases
              .filter(phase => phase.kill_chain_name === 'mitre-attack')
              .map(phase => phase.phase_name);
            
            mitreTactics.forEach(tactic => {
              if (!techniques[tactic]) {
                techniques[tactic] = [];
              }
              
              techniques[tactic].push({
                id: mitreRef.external_id,
                name: obj.name,
                description: obj.description,
                url: mitreRef.url,
                tactics: mitreTactics,
                platforms: obj.x_mitre_platforms || []
              });
            });
          }
        }
      });
      
      // Sort techniques by ID within each tactic
      Object.keys(techniques).forEach(tactic => {
        techniques[tactic].sort((a, b) => {
          const numA = parseInt(a.id.substring(1));
          const numB = parseInt(b.id.substring(1));
          return numA - numB;
        });
      });
      
      setData({ techniques, tactics });
      setLoading(false);
      
      // Initialize all tactics as expanded
      const expanded = {};
      tacticOrder.forEach(tactic => {
        expanded[tactic] = true;
      });
      setExpandedTactics(expanded);
    } catch (error) {
      console.error('Error fetching MITRE data:', error);
      setLoading(false);
    }
  };

  const toggleTactic = (tactic) => {
    setExpandedTactics(prev => ({
      ...prev,
      [tactic]: !prev[tactic]
    }));
  };

  const filterTechniques = (techniques) => {
    if (!searchTerm) return techniques;
    return techniques.filter(tech => 
      tech.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      tech.id.toLowerCase().includes(searchTerm.toLowerCase())
    );
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-slate-900 flex items-center justify-center">
        <div className="text-white text-xl">Loading MITRE ATT&CK Matrix...</div>
      </div>
    );
  }

  if (!data) {
    return (
      <div className="min-h-screen bg-slate-900 flex items-center justify-center">
        <div className="text-white text-xl">Error loading data</div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-900 text-white p-6">
      {/* Header */}
      <div className="max-w-full mx-auto mb-6">
        <h1 className="text-4xl font-bold mb-2 text-center">
          MITRE ATT&CK® Matrix for Enterprise
        </h1>
        <p className="text-slate-400 text-center mb-6">
          Interactive visualization of tactics and techniques
        </p>
        
        {/* Search Bar */}
        <div className="relative max-w-2xl mx-auto">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-slate-400" size={20} />
          <input
            type="text"
            placeholder="Search techniques by name or ID (e.g., T1566)..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-10 pr-10 py-3 bg-slate-800 border border-slate-700 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
          {searchTerm && (
            <button
              onClick={() => setSearchTerm('')}
              className="absolute right-3 top-1/2 transform -translate-y-1/2 text-slate-400 hover:text-white"
            >
              <X size={20} />
            </button>
          )}
        </div>
        
        {searchTerm && (
          <div className="text-center mt-4 text-slate-400">
            Filtering results for "{searchTerm}"
          </div>
        )}
      </div>

      {/* Matrix Grid */}
      <div className="overflow-x-auto">
        <div className="inline-flex gap-2 min-w-full pb-4">
          {tacticOrder.map(tacticId => {
            const techniquesList = data.techniques[tacticId] || [];
            const filteredTechniques = filterTechniques(techniquesList);
            const isExpanded = expandedTactics[tacticId];
            
            if (searchTerm && filteredTechniques.length === 0) {
              return null;
            }
            
            return (
              <div key={tacticId} className="flex-shrink-0" style={{ width: '280px' }}>
                {/* Tactic Header */}
                <div className="bg-blue-600 p-4 rounded-t-lg">
                  <button
                    onClick={() => toggleTactic(tacticId)}
                    className="w-full flex items-center justify-between text-left group"
                  >
                    <h2 className="text-lg font-bold">
                      {tacticNames[tacticId]}
                    </h2>
                    {isExpanded ? 
                      <ChevronUp size={20} className="group-hover:scale-110 transition-transform" /> : 
                      <ChevronDown size={20} className="group-hover:scale-110 transition-transform" />
                    }
                  </button>
                  <div className="text-sm opacity-90 mt-1">
                    {filteredTechniques.length} technique{filteredTechniques.length !== 1 ? 's' : ''}
                  </div>
                </div>
                
                {/* Techniques */}
                {isExpanded && (
                  <div className="bg-slate-800 rounded-b-lg border border-slate-700 border-t-0 max-h-[600px] overflow-y-auto">
                    {filteredTechniques.map(technique => (
                      <button
                        key={technique.id}
                        onClick={() => setSelectedTechnique(technique)}
                        className="w-full text-left p-3 border-b border-slate-700 hover:bg-slate-700 transition-colors group"
                      >
                        <div className="font-mono text-sm text-blue-400 mb-1">
                          {technique.id}
                        </div>
                        <div className="text-sm font-medium group-hover:text-blue-300 transition-colors">
                          {technique.name}
                        </div>
                      </button>
                    ))}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* Technique Detail Modal */}
      {selectedTechnique && (
        <div className="fixed inset-0 bg-black bg-opacity-75 flex items-center justify-center p-4 z-50">
          <div className="bg-slate-800 rounded-lg max-w-3xl w-full max-h-[90vh] overflow-y-auto">
            <div className="sticky top-0 bg-slate-800 border-b border-slate-700 p-6 flex justify-between items-start">
              <div>
                <div className="font-mono text-blue-400 text-lg mb-2">
                  {selectedTechnique.id}
                </div>
                <h3 className="text-2xl font-bold mb-2">
                  {selectedTechnique.name}
                </h3>
                <div className="flex flex-wrap gap-2 mt-3">
                  {selectedTechnique.tactics.map(tactic => (
                    <span
                      key={tactic}
                      className="px-3 py-1 bg-blue-600 rounded-full text-sm"
                    >
                      {tacticNames[tactic]}
                    </span>
                  ))}
                </div>
              </div>
              <button
                onClick={() => setSelectedTechnique(null)}
                className="text-slate-400 hover:text-white p-2 rounded-lg hover:bg-slate-700 transition-colors"
              >
                <X size={24} />
              </button>
            </div>
            
            <div className="p-6">
              <div className="mb-6">
                <h4 className="text-lg font-semibold mb-3">Description</h4>
                <p className="text-slate-300 leading-relaxed whitespace-pre-wrap">
                  {selectedTechnique.description}
                </p>
              </div>
              
              {selectedTechnique.platforms && selectedTechnique.platforms.length > 0 && (
                <div className="mb-6">
                  <h4 className="text-lg font-semibold mb-3">Platforms</h4>
                  <div className="flex flex-wrap gap-2">
                    {selectedTechnique.platforms.map(platform => (
                      <span
                        key={platform}
                        className="px-3 py-1 bg-slate-700 rounded-lg text-sm"
                      >
                        {platform}
                      </span>
                    ))}
                  </div>
                </div>
              )}
              
              <div className="pt-4 border-t border-slate-700">
                <a
                  href={selectedTechnique.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg transition-colors"
                >
                  <span>View on MITRE ATT&CK</span>
                  <ExternalLink size={16} />
                </a>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Footer */}
      <div className="text-center mt-8 text-slate-500 text-sm">
        <p>Data sourced from the MITRE ATT&CK® framework</p>
        <p className="mt-1">
          <a 
            href="https://attack.mitre.org/" 
            target="_blank" 
            rel="noopener noreferrer"
            className="hover:text-slate-300 underline"
          >
            attack.mitre.org
          </a>
        </p>
      </div>
    </div>
  );
};

export default MitreAttackMatrix;