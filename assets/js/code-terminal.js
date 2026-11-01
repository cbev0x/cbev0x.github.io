document.addEventListener("DOMContentLoaded", function () {
  var blocks = document.querySelectorAll(".page__content div.highlighter-rouge, .page__content figure.highlight");
  blocks.forEach(function (block) {
    var wrap = document.createElement("div");
    wrap.className = "code-term";
    block.parentNode.insertBefore(wrap, block);

    var bar = document.createElement("div");
    bar.className = "code-term__bar";

    ["r", "y", "g"].forEach(function (c) {
      var d = document.createElement("span");
      d.className = "code-term__dot code-term__dot--" + c;
      bar.appendChild(d);
    });

    var lang = (block.className.match(/language-(\w+)/) || [])[1] || "shell";
    var label = document.createElement("span");
    label.className = "code-term__lang";
    label.textContent = lang;
    bar.appendChild(label);

    var btn = document.createElement("button");
    btn.className = "code-term__copy";
    btn.type = "button";
    btn.textContent = "copy";
    btn.addEventListener("click", function () {
      var codeEl = block.querySelector(".rouge-code pre, pre.highlight code, pre > code, pre");
      var text = codeEl ? codeEl.innerText : block.innerText;
      navigator.clipboard.writeText(text.replace(/\n$/, "")).then(function () {
        btn.textContent = "copied";
        setTimeout(function () { btn.textContent = "copy"; }, 1500);
      });
    });
    bar.appendChild(btn);

    wrap.appendChild(bar);
    wrap.appendChild(block);
  });
});
