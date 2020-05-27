package cwm
import(
	"io/ioutil"
	"github.com/go-yaml/yaml"
	"github.com/jptosso/coraza/pkg/rproxy"
)

type Config struct{
	Applications []string `yaml:"applications"` // application config paths
	LogPath string `yaml:"log_path"`
	User string `yaml:"user"`
	Group string `yaml:"group"`

	//MonitorInterval int `yaml:"monitor_interval"`
	//HealthEventsInterval int `yaml:"health_events_interval"`
	//HealthEventsErrors  int `yaml:"health_events_errors"`
}
type ConfigFile struct{
	Cwm *Config `yaml:"cwm"`
	loadedProxies []*rproxy.Rproxy
	loadedFiles []string
}

func (c *ConfigFile) Init(path string) error{
	data, err := ioutil.ReadFile(path)
	if err != nil{
		return err
	}
	err = yaml.Unmarshal(data, c)
	if err != nil{
		return err
	}
	c.loadedProxies = []*rproxy.Rproxy{}
	c.loadedFiles = []string{}
	for _, app := range c.Cwm.Applications {
		rconfig := rproxy.Config{}
		data, err := ioutil.ReadFile(app)
		if err != nil{
			return err
		}
	    err = yaml.Unmarshal([]byte(data), &rconfig)
	    if err != nil {
	        return err
	    }		
		c.loadedProxies = append(c.loadedProxies, rconfig.Rproxy)
		c.loadedFiles = append(c.loadedFiles, app)
	}
	return nil
}
func (c *ConfigFile) GetProxies() []*rproxy.Rproxy{
	return c.loadedProxies
}

func (c *ConfigFile) GetApplications() []*rproxy.ConfigApplication{
	ret := []*rproxy.ConfigApplication{}
	for _, p := range c.GetProxies(){
		ret = append(ret, p.Application)
	}
	return ret
}

func (c *ConfigFile) GetProxyById(id string) *rproxy.Rproxy{
	for _, p := range c.GetProxies(){
		if p.Application.Id == id{
			return p
		}
	}
	return nil
}

func (c *ConfigFile) GetProxyFileById(id string) string{
	for i, p := range c.GetProxies(){
		if p.Application.Id == id{
			return c.loadedFiles[i]
		}
	}
	return ""
}
