<script lang="ts">
  import { onMount } from "svelte";
  import {
    adjustSideBySideZoom,
    createCockpitState,
    DESKTOP_TABS,
    formatRussianItems,
    handleCockpitKeydown,
    onWindowBlur,
    onWindowFocus,
  } from "./lib/cockpitState.mjs";

  let state = createCockpitState();
  let vaultPath = "";
  let passphrase = "";
  let statusMessage = "Locked (CachyOS Zero-Knowledge Mode)";
  let mediaItems: Array<{ id: string; original_name: string; mime_type: string }> = [];
  let searchQuery = "";

  onMount(() => {
    const keyListener = (e: KeyboardEvent) => {
      state = handleCockpitKeydown(state, e);
    };
    const blurListener = () => {
      state = onWindowBlur(state);
    };
    const focusListener = () => {
      state = onWindowFocus(state);
    };
    window.addEventListener("keydown", keyListener);
    window.addEventListener("blur", blurListener);
    window.addEventListener("focus", focusListener);
    return () => {
      window.removeEventListener("keydown", keyListener);
      window.removeEventListener("blur", blurListener);
      window.removeEventListener("focus", focusListener);
    };
  });

  async function tryInvoke(cmd: string, args: Record<string, unknown>) {
    try {
      const { invoke } = await import("@tauri-apps/api/core");
      return await invoke(cmd, args);
    } catch (err) {
      statusMessage = String(err);
      return null;
    }
  }

  async function handleUnlock() {
    const res = await tryInvoke("unlock_vault", { vaultDir: vaultPath, passphrase });
    if (res) {
      state = { ...state, unlocked: true };
      passphrase = "";
      await refreshMedia();
      statusMessage = "Unlocked • RAM mlock active";
    }
  }

  async function handlePanicLock() {
    await tryInvoke("lock_vault", {});
    state = handleCockpitKeydown(state, { key: "l", ctrlKey: true });
    mediaItems = [];
    statusMessage = "Locked • Keys zeroized";
  }

  async function refreshMedia() {
    const items = (await tryInvoke("list_media", {})) as typeof mediaItems | null;
    if (items) {
      mediaItems = items;
      state = { ...state, totalItems: items.length, selectedIndex: 0 };
    }
  }

  async function handleDrop(e: DragEvent) {
    e.preventDefault();
    if (!state.unlocked || !e.dataTransfer?.files?.length) return;
    const paths = Array.from(e.dataTransfer.files).map((f) => (f as unknown as { path?: string }).path || f.name);
    await tryInvoke("import_paths", { paths });
    await refreshMedia();
  }
</script>

{#if state.privacyCurtainActive}
  <div class="privacy-curtain">
    <h2>MeshVault Privacy Shield</h2>
    <p>Окно скрыто при потере фокуса (CachyOS Wayland Guard)</p>
  </div>
{/if}

<div class="cockpit-shell" on:dragover|preventDefault on:drop={handleDrop}>
  <aside class="cockpit-sidebar">
    <strong>MeshVault CachyOS</strong>
    {#each DESKTOP_TABS as tab, idx}
      <button
        class="nav-btn {state.activeTab === tab ? 'active' : ''}"
        on:click={() => (state = { ...state, activeTab: tab })}
      >
        [{idx + 1}] {tab.toUpperCase()}
      </button>
    {/each}
    <div style="margin-top: auto;">
      {#if state.unlocked}
        <button class="nav-btn" on:click={handlePanicLock}>Lock (Ctrl+L)</button>
      {/if}
    </div>
  </aside>

  <main class="cockpit-main">
    {#if !state.unlocked}
      <h2>Разблокировка сейфа</h2>
      <div style="display:flex; flex-direction:column; gap:10px; max-width:420px;">
        <input bind:value={vaultPath} placeholder="/home/user/Vault" />
        <input type="password" bind:value={passphrase} placeholder="Мастер-пароль" />
        <button on:click={handleUnlock}>Открыть контейнер</button>
      </div>
    {:else if state.sideBySideEnabled && mediaItems.length >= 2}
      <div style="display:flex; gap:12px; margin-bottom:10px;">
        <button on:click={() => (state = adjustSideBySideZoom(state, 0.5))}>Zoom +</button>
        <button on:click={() => (state = adjustSideBySideZoom(state, -0.5))}>Zoom -</button>
        <span>Синхронный зум: {state.syncZoomLevel}x (S — выход)</span>
      </div>
      <div class="side-by-side-grid">
        <img
          src={`meshvault://media/${mediaItems[state.sideBySidePrimaryIndex]?.id}`}
          alt="Left comparison"
          style={`transform: scale(${state.syncZoomLevel}); object-fit: contain; width: 100%;`}
        />
        <img
          src={`meshvault://media/${mediaItems[state.sideBySideSecondaryIndex]?.id}`}
          alt="Right comparison"
          style={`transform: scale(${state.syncZoomLevel}); object-fit: contain; width: 100%;`}
        />
      </div>
    {:else}
      <h2>{state.activeTab.toUpperCase()} — {formatRussianItems(mediaItems.length)}</h2>
      {#if state.activeTab === "search"}
        <input bind:value={searchQuery} placeholder="Поиск по каталогу (Ctrl+F)" />
      {/if}
      <p>Перетащите файлы или папки сюда для импорта (Drag & Drop), hjkl — навигация, S — Side-by-Side.</p>
      <ul>
        {#each mediaItems as item, idx}
          <li style={idx === state.selectedIndex ? "color: #5e72eb; font-weight: bold;" : ""}>
            {item.original_name} ({item.mime_type})
          </li>
        {/each}
      </ul>
    {/if}
  </main>

  <footer class="cockpit-statusbar">
    <span>{statusMessage}</span>
    <span>Hotkeys: 1-6 вкладки | hjkl навигация | S сравнение | Ctrl+F поиск | Ctrl+L блокировка</span>
  </footer>
</div>
