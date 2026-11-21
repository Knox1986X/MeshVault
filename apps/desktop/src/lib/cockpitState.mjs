export const DESKTOP_TABS = [
  "overview",
  "folders",
  "gallery",
  "search",
  "security",
  "sync",
];

/**
 * Pure Dark Cockpit controller for CachyOS desktop keyboard navigation,
 * focus-loss privacy curtain, panic lock (Ctrl+L), and Side-by-Side comparison.
 */
export function createCockpitState() {
  return {
    unlocked: false,
    privacyCurtainActive: false,
    activeTab: "overview",
    selectedIndex: 0,
    totalItems: 0,
    searchFocused: false,
    sideBySideEnabled: false,
    sideBySidePrimaryIndex: 0,
    sideBySideSecondaryIndex: 1,
    syncZoomLevel: 1.0,
    locale: "ru",
  };
}

export function onWindowBlur(state) {
  return {
    ...state,
    privacyCurtainActive: state.unlocked,
  };
}

export function onWindowFocus(state) {
  return {
    ...state,
    privacyCurtainActive: false,
  };
}

export function handleCockpitKeydown(state, event) {
  const key = event.key;
  const ctrl = Boolean(event.ctrlKey || event.metaKey);

  if (ctrl && key.toLowerCase() === "l") {
    return {
      ...state,
      unlocked: false,
      privacyCurtainActive: false,
      sideBySideEnabled: false,
      activeTab: "overview",
    };
  }

  if (!state.unlocked) {
    return state;
  }

  if (ctrl && key.toLowerCase() === "f") {
    return {
      ...state,
      activeTab: "search",
      searchFocused: true,
    };
  }

  if (key >= "1" && key <= "6") {
    const tabIdx = Number(key) - 1;
    return {
      ...state,
      activeTab: DESKTOP_TABS[tabIdx] ?? state.activeTab,
      searchFocused: false,
    };
  }

  if (key === "j" || key === "l" || key === "ArrowRight" || key === "ArrowDown") {
    const next =
      state.totalItems > 0 ? Math.min(state.selectedIndex + 1, state.totalItems - 1) : 0;
    return { ...state, selectedIndex: next };
  }

  if (key === "k" || key === "h" || key === "ArrowLeft" || key === "ArrowUp") {
    const prev = state.totalItems > 0 ? Math.max(state.selectedIndex - 1, 0) : 0;
    return { ...state, selectedIndex: prev };
  }

  if (key === " " || key.toLowerCase() === "s") {
    if (key.toLowerCase() === "s" && state.totalItems >= 2) {
      const nextEnabled = !state.sideBySideEnabled;
      return {
        ...state,
        sideBySideEnabled: nextEnabled,
        sideBySidePrimaryIndex: state.selectedIndex,
        sideBySideSecondaryIndex: (state.selectedIndex + 1) % state.totalItems,
      };
    }
    return state;
  }

  return state;
}

export function adjustSideBySideZoom(state, delta) {
  const clamped = Math.max(1.0, Math.min(8.0, Number((state.syncZoomLevel + delta).toFixed(2))));
  return { ...state, syncZoomLevel: clamped };
}

export function formatRussianItems(count) {
  const mod100 = Math.abs(count) % 100;
  const mod10 = mod100 % 10;
  let form = "объектов";
  if (mod100 < 11 || mod100 > 14) {
    if (mod10 === 1) form = "объект";
    else if (mod10 >= 2 && mod10 <= 4) form = "объекта";
  }
  return `${count} ${form}`;
}
