import argparse
import json
import sqlite3

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("cfi-sqlite")

DB_PATH = None


def _connect():
    return sqlite3.connect(DB_PATH)


@mcp.tool()
def list_tables() -> str:
    """列出 CFI 检测结果数据库中的所有表及其行数。"""
    conn = _connect()
    try:
        cur = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        )
        tables = [r[0] for r in cur.fetchall()]
        info = []
        for t in tables:
            cnt = conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
            info.append({"table": t, "rows": cnt})
        return json.dumps(info, ensure_ascii=False)
    finally:
        conn.close()


@mcp.tool()
def describe_table(table: str) -> str:
    """查看某张表的列结构（列名与类型）。"""
    conn = _connect()
    try:
        cur = conn.execute(f"PRAGMA table_info({table})")
        cols = [{"name": r[1], "type": r[2]} for r in cur.fetchall()]
        return json.dumps(cols, ensure_ascii=False)
    finally:
        conn.close()


@mcp.tool()
def query(sql: str) -> str:
    """对 CFI 检测结果数据库执行只读 SQL 查询（仅 SELECT），返回 JSON 结果（最多 200 行）。
    可用表：summary, modules, so_files, name_table, so_functions。"""
    stmt = sql.strip()
    if not stmt.lower().startswith("select"):
        return json.dumps({"error": "仅允许 SELECT 查询"}, ensure_ascii=False)
    if ";" in stmt.rstrip(";"):
        return json.dumps({"error": "仅允许单条语句"}, ensure_ascii=False)
    conn = _connect()
    conn.row_factory = sqlite3.Row
    try:
        cur = conn.execute(stmt)
        rows = [dict(r) for r in cur.fetchmany(200)]
        return json.dumps({"rowcount": len(rows), "rows": rows}, ensure_ascii=False)
    except Exception as e:
        return json.dumps({"error": str(e)}, ensure_ascii=False)
    finally:
        conn.close()


def main():
    global DB_PATH
    parser = argparse.ArgumentParser(description="CFI SQLite MCP Server")
    parser.add_argument("--db", required=True, help="cfi_detection.sqlite 路径")
    args = parser.parse_args()
    DB_PATH = args.db
    mcp.run()


if __name__ == "__main__":
    main()
