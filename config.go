package cdncheck

import (
	"gopkg.in/yaml.v3"
	"io/ioutil"
	"log"
	"os"
)

func ReadAKSKConfig(filePath string) (*AKSKConfig, error) {
	_, err := os.Stat(filePath)
	if os.IsNotExist(err) {
		log.Println("配置文件为空！即将创建配置文件，请配置config.yaml后再次运行")

		configContent := []byte(`
TencentId: ""
TencentKey: ""
AlibabaId: ""
AlibabaKey: ""
BaiduId: ""
BaiduKey: ""
VolcengineId: ""
VolcengineKey: ""
HuaweiID: ""
HuaweiKey: ""
		`)
		err = os.WriteFile("config.yaml", configContent, 0644)
		if err != nil {
			log.Fatal("创建配置文件失败", err)
		}
		os.Exit(1)
	}

	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var akskConfig AKSKConfig
	err = yaml.Unmarshal(data, &akskConfig)
	if err != nil {
		return nil, err
	}

	return &akskConfig, nil
}
