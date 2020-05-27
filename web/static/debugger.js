function detect_keys(e){
    var evtobj=window.event? event : e
    //ctrl + y
    if (evtobj.ctrlKey && evtobj.keyCode == 68){
    	alert("Apretaste CTRL+D")
    	var div = "<div style='z-index: 99999999;background-color: #ddd;border-radius:0.3px;position: absolute; top: 100px;left: 20%;width: 40%;height:80%;border:1px solid #ddd;'>" +
    	"<h4>Coraza Web Application Firewall</h4>" +
    	"<pre>" + cw_tx_debug + "</pre></div>";
    	document.body.innerHTML += div;
    }
}
document.onkeypress=detect_keys