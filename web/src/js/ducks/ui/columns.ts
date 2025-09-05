import { createSlice, PayloadAction } from "@reduxjs/toolkit";

// 存储每个列名对应的像素宽度
export type ColumnWidthsState = Record<string, number>;

const STORAGE_KEY = "mitmweb_column_widths";

// 从原样式推导出的默认宽度（像素）。未列出的列将自适应剩余空间。
export const DEFAULT_COLUMN_WIDTHS: Record<string, number> = {
    tls: 10,
    index: 48, // 原 4ch，这里近似为 48px
    icon: 32,
    method: 60,
    process: 200,
    version: 80,
    status: 50,
    size: 70,
    time: 50,
    timestamp: 170,
    comment: 150,
    quickactions: 0,
};

function loadInitial(): ColumnWidthsState {
    if (typeof window === "undefined") return {};
    try {
        const s = window.localStorage.getItem(STORAGE_KEY);
        if (!s) return {};
        const parsed = JSON.parse(s);
        if (parsed && typeof parsed === "object") return parsed as ColumnWidthsState;
        return {};
    } catch {
        return {};
    }
}

const initialState: ColumnWidthsState = loadInitial();

const columnsSlice = createSlice({
    name: "columns",
    initialState,
    reducers: {
        setWidth(
            state,
            action: PayloadAction<{ name: string; width: number }>,
        ) {
            const { name } = action.payload;
            const width = Math.max(24, Math.round(action.payload.width));
            state[name] = width;
            // 简单持久化到 localStorage（可选）
            try {
                window.localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
            } catch {
                // ignore
            }
        },
        reset(state) {
            for (const k of Object.keys(state)) delete state[k];
            try {
                window.localStorage.removeItem(STORAGE_KEY);
            } catch {
                // ignore
            }
        },
    },
});

export const { setWidth: setColumnWidth, reset: resetColumnWidths } =
    columnsSlice.actions;

export default columnsSlice.reducer;
