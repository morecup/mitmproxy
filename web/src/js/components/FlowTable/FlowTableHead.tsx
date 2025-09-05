import * as React from "react";
import classnames from "classnames";
import * as columns from "./FlowColumns";

import { setSort } from "../../ducks/flows";
import { useAppDispatch, useAppSelector } from "../../ducks";
import { setColumnWidth } from "../../ducks/ui/columns";

export default React.memo(function FlowTableHead() {
    const dispatch = useAppDispatch();
    const sortDesc = useAppSelector((state) => state.flows.sort.desc);
    const sortColumn = useAppSelector((state) => state.flows.sort.column);
    const displayColumnNames = useAppSelector(
        (state) => state.options.web_columns,
    );
    const widths = useAppSelector((state) => state.ui.columns);

    const sortType = sortDesc ? "sort-desc" : "sort-asc";
    const displayColumns = displayColumnNames
        .map((x) => columns[x])
        .filter((x) => x)
        .concat(columns.quickactions);

    const onResizeStart = React.useCallback(
        (e: React.MouseEvent, colName: string) => {
            e.preventDefault();
            e.stopPropagation();

            const th = (e.currentTarget as HTMLElement)
                .parentElement as HTMLTableCellElement | null;
            if (!th) return;

            const startX = e.clientX;
            const startWidth = th.getBoundingClientRect().width;

            const onMouseMove = (ev: MouseEvent) => {
                const delta = ev.clientX - startX;
                const newWidth = startWidth + delta;
                dispatch(setColumnWidth({ name: colName, width: newWidth }));
            };
            const onMouseUp = () => {
                window.removeEventListener("mousemove", onMouseMove);
                window.removeEventListener("mouseup", onMouseUp);
            };

            window.addEventListener("mousemove", onMouseMove);
            window.addEventListener("mouseup", onMouseUp);
        },
        [dispatch],
    );

    return (
        <tr>
            {displayColumns.map((Column) => (
                <th
                    className={classnames(
                        `col-${Column.name}`,
                        sortColumn === Column.name && sortType,
                    )}
                    key={Column.name}
                    onClick={() =>
                        dispatch(
                            setSort({
                                column:
                                    Column.name === sortColumn && sortDesc
                                        ? undefined
                                        : Column.name,
                                desc:
                                    Column.name !== sortColumn
                                        ? false
                                        : !sortDesc,
                            }),
                        )
                    }
                >
                    {Column.headerName}
                    {Column.name !== "quickactions" && (
                        <span
                            className="col-resizer"
                            onMouseDown={(e) =>
                                onResizeStart(e, Column.name)
                            }
                            onClick={(e) => e.stopPropagation()}
                            title={
                                widths?.[Column.name]
                                    ? `${widths[Column.name]}px`
                                    : undefined
                            }
                        />
                    )}
                </th>
            ))}
        </tr>
    );
});
