import test from "node:test";
import assert from "node:assert/strict";

import {
  adjustSideBySideZoom,
  createCockpitState,
  formatRussianItems,
  handleCockpitKeydown,
  onWindowBlur,
  onWindowFocus,
} from "../src/lib/cockpitState.mjs";

test("Ctrl+L immediately locks vault and clears Side-by-Side mode", () => {
  let state = {
    ...createCockpitState(),
    unlocked: true,
    sideBySideEnabled: true,
    activeTab: "gallery",
  };
  state = handleCockpitKeydown(state, { key: "l", ctrlKey: true });
  assert.equal(state.unlocked, false);
  assert.equal(state.sideBySideEnabled, false);
  assert.equal(state.activeTab, "overview");
});

test("Blur activates privacy curtain only when unlocked and focus restores it", () => {
  const locked = onWindowBlur(createCockpitState());
  assert.equal(locked.privacyCurtainActive, false);

  const unlocked = { ...createCockpitState(), unlocked: true };
  const blurred = onWindowBlur(unlocked);
  assert.equal(blurred.privacyCurtainActive, true);

  const refocused = onWindowFocus(blurred);
  assert.equal(refocused.privacyCurtainActive, false);
});

test("hjkl navigation, 1-6 tabs, Ctrl+F search, and Side-by-Side synchronized zoom", () => {
  let state = { ...createCockpitState(), unlocked: true, totalItems: 5 };
  state = handleCockpitKeydown(state, { key: "3" });
  assert.equal(state.activeTab, "gallery");

  state = handleCockpitKeydown(state, { key: "j" });
  state = handleCockpitKeydown(state, { key: "j" });
  assert.equal(state.selectedIndex, 2);

  state = handleCockpitKeydown(state, { key: "k" });
  assert.equal(state.selectedIndex, 1);

  state = handleCockpitKeydown(state, { key: "s" });
  assert.equal(state.sideBySideEnabled, true);
  assert.equal(state.sideBySidePrimaryIndex, 1);
  assert.equal(state.sideBySideSecondaryIndex, 2);

  state = adjustSideBySideZoom(state, 1.5);
  assert.equal(state.syncZoomLevel, 2.5);

  state = handleCockpitKeydown(state, { key: "f", ctrlKey: true });
  assert.equal(state.activeTab, "search");
  assert.equal(state.searchFocused, true);
});

test("Russian plurals format correctly on desktop status bar", () => {
  assert.equal(formatRussianItems(1), "1 объект");
  assert.equal(formatRussianItems(2), "2 объекта");
  assert.equal(formatRussianItems(5), "5 объектов");
  assert.equal(formatRussianItems(21), "21 объект");
});
