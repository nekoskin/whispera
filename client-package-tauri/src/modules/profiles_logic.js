export let profiles = [];

export function loadProfiles() {
    try {
        const saved = localStorage.getItem('whispera_profiles');
        if (saved) profiles = JSON.parse(saved);
    } catch (e) {
        console.error('Profiles load error:', e);
        profiles = [];
    }
}

export function saveProfiles() {
    try {
        localStorage.setItem('whispera_profiles', JSON.stringify(profiles));
    } catch (e) {
        console.error('Profiles save error:', e);
    }
}
