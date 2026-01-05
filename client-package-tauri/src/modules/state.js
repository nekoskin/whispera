// Состояние приложения
export const appState = {
    connected: false,
    connecting: false,
    goClientPath: null,
    traffic: {
        inbound: { bytes: 0, packets: 0 },
        outbound: { bytes: 0, packets: 0 },
        speed: { up: 0, down: 0 },
        history: [] // Последние 60 секунд
    },
    quickConnectInProgress: false // Защита от повторных вызовов
};
