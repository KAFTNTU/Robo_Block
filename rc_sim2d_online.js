/* RoboBlock 2D - Online Multiplayer Module */
(function(){
  'use strict';

// === ONLINE GLOBALS ===
window.isOnline = false; 
window.serverWs = null;
window.onlineState = "offline";
window.useServerPhysics = false; // TRUE = сервер керує позицією, FALSE = локальна фізика

// ХТО Я? (Сервер скаже: "p1" або "p2")
window.myPID = null; 

// КООРДИНАТИ від сервера
window.serverBotData = { x: 0, y: 0, a: 0 }; // Моя машинка
window.enemyBotData = { x: 0, y: 0, a: 0 };  // Суперник

// === AUTO-START (без кнопки Старт/Стоп) ===
// Ідея: коли підключились ДВА гравці (є enemy у state), через 3с автоматично запускаємо Block/Blockly програму.
// Це прибирає потребу тиснути "Старт" вручну.
window.__rcOnlineAutoStart = window.__rcOnlineAutoStart || { started:false, timer:null };

function _tryStartProgram(){
  try{
    const sim = window.RCSim2D && window.RCSim2D._sim;
    if (!sim) return;
    if (!sim.running && typeof sim.startProgram === 'function'){
      sim.startProgram();
    }
  }catch(e){}
}

function _scheduleAutoStart(hasEnemy){
  try{
    if (!hasEnemy) return;
    const st = window.__rcOnlineAutoStart;
    if (!st || st.started) return;
    st.started = true;
    if (st.timer) { try{ clearTimeout(st.timer); }catch(e){} }
    st.timer = setTimeout(_tryStartProgram, 3000);
  }catch(e){}
}


// === ПІДКЛЮЧЕННЯ ДО СЕРВЕРА ===
// Helper: update the dot inside the simulator's "Сумо онлайн" button.
function _syncSimDot(state){
  try{
    const sim = window.RCSim2D && window.RCSim2D._sim;
    if (sim && typeof sim.setOnlineStatus === 'function') sim.setOnlineStatus(state||'');
  }catch(e){}
}

window.setSumoRoom = function(room){
  try{
    const v = String(room||'').trim();
    if (!v) { localStorage.removeItem('rc_online_room'); return; }
    localStorage.setItem('rc_online_room', v);
  }catch(e){}
};

window.connectToSumo = function() {
    console.log("Connecting to sumo server...");
    window.onlineState = "connecting";
    _syncSimDot('connecting');

    // Room code: taken from localStorage (set via UI). No prompts here.
    let room = (localStorage.getItem('rc_online_room')||'').trim();
    if (!room){
      console.warn('[SUMO] No room code set (rc_online_room).');
      window.onlineState = 'offline';
      _syncSimDot('');
      return;
    }

    // WebSocket адреса вашого сервера
    const wsUrl = `wss://rc-sumo-server.kafrdrapv1.workers.dev/ws?room=${encodeURIComponent(room)}`;
    window.serverWs = new WebSocket(wsUrl);

    window.serverWs.onopen = () => {
        try{ window.__rcOnlineAutoStart && (window.__rcOnlineAutoStart.started=false); }catch(e){}

        window.isOnline = true;
        window.onlineState = "online";
        window.useServerPhysics = true; // Вмикаємо серверну фізику
        console.log("✅ ONLINE MODE ACTIVATED!"); 
        _syncSimDot('connected');
    };

    window.serverWs.onmessage = (e) => {
        try {
            const d = JSON.parse(e.data);

            // 1. СЕРВЕР КАЖЕ, ХТО ТИ (Приходить одразу при вході)
            if (d.t === "hello") {
                window.myPID = d.pid; // "p1" або "p2"
                console.log(`✅ ТВОЯ РОЛЬ: ${window.myPID}`);
            }

            // 2. ОТРИМУЄМО КООРДИНАТИ (Приходить постійно ~10Hz)
            if (d.t === "state" && d.bots) {
                // Якщо сервер ще не сказав, хто ми — ігноруємо
                if (!window.myPID) return;

                const me = window.myPID;                 
                const enemy = (me === "p1") ? "p2" : "p1";

                // Оновлюємо СЕБЕ (координати для відображення)
                if (d.bots[me]) {
                    window.serverBotData = {
                        x: d.bots[me].x,
                        y: d.bots[me].y,
                        a: d.bots[me].a
                    };
                }

	                // Оновлюємо ВОРОГА (щоб знати де він)
	                if (d.bots[enemy]) {
	                    window.enemyBotData = {
	                        x: d.bots[enemy].x,
	                        y: d.bots[enemy].y,
	                        a: d.bots[enemy].a
	                    };
	                }

	                // Автостарт коли другий гравець підключився
	                _scheduleAutoStart(!!d.bots[enemy]);
	            }
        } catch(err){
            console.error("WebSocket message error:", err);
        }
    };

    window.serverWs.onerror = () => {
        try{ if (window.__rcOnlineAutoStart && window.__rcOnlineAutoStart.timer){ clearTimeout(window.__rcOnlineAutoStart.timer); }
              if (window.__rcOnlineAutoStart) window.__rcOnlineAutoStart.started=false; }catch(e){}

        window.isOnline = false;
        window.onlineState = "offline";
        window.useServerPhysics = false;
        console.error("❌ WebSocket error");
        _syncSimDot('error');
    };

    window.serverWs.onclose = () => {
        try{ if (window.__rcOnlineAutoStart && window.__rcOnlineAutoStart.timer){ clearTimeout(window.__rcOnlineAutoStart.timer); }
              if (window.__rcOnlineAutoStart) window.__rcOnlineAutoStart.started=false; }catch(e){}

        window.isOnline = false;
        window.onlineState = "offline";
        window.useServerPhysics = false;
        window.myPID = null;
        console.log("🔴 OFFLINE MODE"); 
        _syncSimDot('');
    };
};

// === ВІДПРАВКА КОМАНД НА СЕРВЕР ===
window.sendInputToServer = function(leftWheel, rightWheel) {
    if (window.isOnline && window.serverWs && window.serverWs.readyState === WebSocket.OPEN) {
        try {
            window.serverWs.send(JSON.stringify({
                t: "input",
                l: leftWheel,   // -100 до 100
                r: rightWheel   // -100 до 100
            }));
        } catch(e) {
            console.error("Failed to send input:", e);
        }
    }
};

// (Крапку/індикатор тепер малює сам симулятор у кнопці "Сумо онлайн".)

console.log("✅ RCSim2D Online Module loaded");

})();
