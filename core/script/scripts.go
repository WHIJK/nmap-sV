/*
 * @Author: OvO
 * @Date: 2024-12-04 18:08:23
 * @LastEditors:
 * @LastEditTime: 2024-12-04 18:09:47
 * @Description: 运行插件
 */
package script

type ScriptInterface interface {
	RunScripts(address string) string
}

// service对应插件
var Scripts = map[string]ScriptInterface{
	"jdwp": &JDWPScript{},
	// 可以添加更多服务和对应的脚本
}
