package plugins

// Plugin represents the interface that all plugins must implement
type Plugin interface {
	// Name returns the name of the plugin
	Name() string
	
	// Version returns the version of the plugin
	Version() string
	
	// Initialize initializes the plugin with the provided configuration
	Initialize(config map[string]interface{}) error
	
	// Start starts the plugin
	Start() error
	
	// Stop stops the plugin
	Stop() error
	
	// Hooks returns a map of hook functions that the plugin provides
	Hooks() map[string]interface{}
}

// Manager handles the loading, initialization, and management of plugins
type Manager struct {
	plugins map[string]Plugin
	hooks   map[string][]interface{}
}

// NewManager creates a new plugin manager
func NewManager() *Manager {
	return &Manager{
		plugins: make(map[string]Plugin),
		hooks:   make(map[string][]interface{}),
	}
}

// RegisterPlugin registers a plugin with the manager
func (m *Manager) RegisterPlugin(plugin Plugin) error {
	name := plugin.Name()
	
	// Check if plugin is already registered
	if _, exists := m.plugins[name]; exists {
		return nil // Plugin already registered
	}
	
	// Register plugin
	m.plugins[name] = plugin
	
	// Register hooks
	for hookName, hookFunc := range plugin.Hooks() {
		if _, exists := m.hooks[hookName]; !exists {
			m.hooks[hookName] = make([]interface{}, 0)
		}
		m.hooks[hookName] = append(m.hooks[hookName], hookFunc)
	}
	
	return nil
}

// InitializePlugins initializes all registered plugins with their configurations
func (m *Manager) InitializePlugins(configs map[string]map[string]interface{}) error {
	for name, plugin := range m.plugins {
		config := configs[name]
		if config == nil {
			config = make(map[string]interface{})
		}
		
		if err := plugin.Initialize(config); err != nil {
			return err
		}
	}
	
	return nil
}

// StartPlugins starts all registered plugins
func (m *Manager) StartPlugins() error {
	for _, plugin := range m.plugins {
		if err := plugin.Start(); err != nil {
			return err
		}
	}
	
	return nil
}

// StopPlugins stops all registered plugins
func (m *Manager) StopPlugins() error {
	for _, plugin := range m.plugins {
		if err := plugin.Stop(); err != nil {
			return err
		}
	}
	
	return nil
}

// GetPlugin returns a plugin by name
func (m *Manager) GetPlugin(name string) Plugin {
	return m.plugins[name]
}

// ExecuteHook executes all functions registered for a specific hook
func (m *Manager) ExecuteHook(hookName string, args ...interface{}) []interface{} {
	results := make([]interface{}, 0)
	
	hooks, exists := m.hooks[hookName]
	if !exists {
		return results
	}
	
	for _, hook := range hooks {
		// This is a simplified implementation
		// In a real implementation, we would use reflection to call the hook function with the provided arguments
		// and collect the results
		results = append(results, hook)
	}
	
	return results
}
