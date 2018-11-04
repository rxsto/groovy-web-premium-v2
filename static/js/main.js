let percentage = 0;

var interval = setInterval(function () {
    if(percentage >= 99) clearInterval(interval);
    percentage++;
    document.getElementById('loading-bar').style.width = percentage + '%';
}, 20);