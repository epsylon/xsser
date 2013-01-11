window.addEventListener("load", addPopup);

function addPopup(){
	var popup = document.createElement("div");
	popup.setAttribute("id", "popup");
	document.body.appendChild(popup);
	popup.addEventListener("click", Alert);
}

function Alert(){
	alert("XSSer");
	popup.style.display="none";
	}

