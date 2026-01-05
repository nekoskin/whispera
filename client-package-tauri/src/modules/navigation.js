import { updateTrafficDisplay } from './stats_ui.js';
import { updateTrafficChart } from './stats_chart.js';
import { renderProfiles } from './profiles_ui.js';

// History State
let historyStack = ['home'];
let currentIndex = 0;

export function initNavigation() {
    const btnBack = document.getElementById('nav-back');
    const btnForward = document.getElementById('nav-forward');

    if (btnBack) {
        btnBack.addEventListener('click', () => {
            if (currentIndex > 0) {
                currentIndex--;
                navigateTo(historyStack[currentIndex], true);
            }
        });
    }

    if (btnForward) {
        btnForward.addEventListener('click', () => {
            if (currentIndex < historyStack.length - 1) {
                currentIndex++;
                navigateTo(historyStack[currentIndex], true);
            }
        });
    }

    updateNavButtons(); // Initial state
}

function updateNavButtons() {
    const btnBack = document.getElementById('nav-back');
    const btnForward = document.getElementById('nav-forward');

    if (btnBack) {
        btnBack.disabled = currentIndex === 0;
        btnBack.style.opacity = currentIndex === 0 ? '0.3' : '1';
        btnBack.style.cursor = currentIndex === 0 ? 'default' : 'pointer';
    }

    if (btnForward) {
        btnForward.disabled = currentIndex >= historyStack.length - 1;
        btnForward.style.opacity = currentIndex >= historyStack.length - 1 ? '0.3' : '1';
        btnForward.style.cursor = currentIndex >= historyStack.length - 1 ? 'default' : 'pointer';
    }
}

export function navigateTo(page, isHistoryNav = false) {
    // History Management
    if (!isHistoryNav) {
        // If navigating to the same page, do nothing (unless it's initial load?)
        if (historyStack[currentIndex] === page) return;

        // Truncate forward history if we branch off
        if (currentIndex < historyStack.length - 1) {
            historyStack = historyStack.slice(0, currentIndex + 1);
        }

        historyStack.push(page);
        currentIndex++;
    }

    updateNavButtons();

    // UI Logic (Prizrak-Box)
    document.querySelectorAll('.nav-icon-btn').forEach(item => {
        item.classList.remove('active');
        if (item.dataset.page === page) {
            item.classList.add('active');
        }
    });

    // Скрываем все страницы
    document.querySelectorAll('.page').forEach(p => {
        p.classList.remove('active');
    });

    // Показываем выбранную страницу
    const targetPage = document.getElementById(`page-${page}`);
    if (targetPage) {
        targetPage.classList.add('active');

        // Обновляем статистику при переходе на страницу статистики
        if (page === 'stats') {
            updateTrafficDisplay();
            updateTrafficChart();
        }

        // Обновляем профили при переходе на страницу профилей
        if (page === 'profiles') {
            renderProfiles();
        }
    }
}

function getPageTitle(page) {
    const titles = {
        'home': 'Главная',
        'settings': 'Настройки',
        'profiles': 'Профили',
        'stats': 'Статистика',
        'logs': 'Журнал',
        'connections': 'Соединения'
    };
    return titles[page] || 'Главная';
}

