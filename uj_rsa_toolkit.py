#!/usr/bin/env python3
"""UJ CryptoBox RSA CTF Toolkit.

Interactive RSA sandbox for CTF workflows, including factoring assistance,
totient and private key recovery, standard decryption, low exponent root
recovery, and Wiener attack.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

import gmpy2
import requests
from Crypto.Util.number import inverse, long_to_bytes

try:
    from rich import box
    from rich.align import Align
    from rich.columns import Columns
    from rich.console import Console
    from rich.panel import Panel
    from rich.prompt import Confirm, Prompt
    from rich.table import Table
    from rich.text import Text
except ImportError:
    print(
        "Error: Missing dependency 'rich'. "
        "Install with: pip install -r requirements.txt"
    )
    sys.exit(1)


MenuItem = Tuple[str, str, str]
FactorList = List[Tuple[int, int]]

FACTORDB_API_URL = "http://factordb.com/api"
VARIABLE_ORDER = ("N", "e", "c", "p", "q", "r", "totient", "d")
VARIABLE_NAME_TO_ATTR = {
    "N": "n",
    "e": "e",
    "c": "c",
    "p": "p",
    "q": "q",
    "r": "r",
    "totient": "totient",
    "d": "d",
}

HEADER_ART = r"""
============================================================
                       UJ CRYPTOBOX
                      RSA CTF TOOLKIT
============================================================
"""

MENU_OPTIONS: Sequence[MenuItem] = (
    ("1", "Set Variable", "Store or update any RSA variable"),
    (
        "2",
        "FactorDB Query",
        "Fetch factors from FactorDB and decide what to store",
    ),
    (
        "3",
        "Calculate Totient",
        "Support one-prime, two-prime, or three-prime layouts",
    ),
    ("4", "Calculate Private Key d", "Compute modular inverse d = e^-1 mod phi"),
    ("5", "Standard Decryption", "Decrypt ciphertext using c, d, and N"),
    (
        "6",
        "N-th Root Attack",
        "Recover plaintext when c is an exact e-th power",
    ),
    (
        "7",
        "Wiener Attack",
        "Recover weak private key d via continued fractions",
    ),
    ("8", "Clear Memory", "Reset all saved variables"),
    ("9", "Exit", "Close the toolkit"),
)


@dataclass
class RSAState:
    """Store RSA variables for the current interactive session."""

    n: Optional[int] = None
    e: Optional[int] = None
    c: Optional[int] = None
    p: Optional[int] = None
    q: Optional[int] = None
    r: Optional[int] = None
    totient: Optional[int] = None
    d: Optional[int] = None
    auto_n_from_primes: bool = False

    def get_variable(self, name: str) -> Optional[int]:
        """Return a variable by menu-facing name."""
        attr_name = VARIABLE_NAME_TO_ATTR[name]
        return getattr(self, attr_name)

    def set_variable(self, name: str, value: Optional[int]) -> None:
        """Set a variable by menu-facing name."""
        attr_name = VARIABLE_NAME_TO_ATTR[name]
        setattr(self, attr_name, value)

    def iter_variables(self) -> Iterable[Tuple[str, Optional[int]]]:
        """Yield variables in stable display order."""
        for variable_name in VARIABLE_ORDER:
            yield variable_name, self.get_variable(variable_name)

    def clear(self) -> None:
        """Reset all variables in memory."""
        for variable_name in VARIABLE_ORDER:
            self.set_variable(variable_name, None)
        self.auto_n_from_primes = False


def normalize_variable_name(raw_name: str) -> Optional[str]:
    """Normalize user input to a supported variable name."""
    cleaned_name = raw_name.strip()
    if not cleaned_name:
        return None

    lower_name = cleaned_name.lower()
    if lower_name == "n":
        return "N"
    if lower_name in ("e", "c", "p", "q", "r", "totient", "d"):
        return lower_name
    return None


def parse_factordb_factors(raw_factors: object) -> Optional[FactorList]:
    """Parse FactorDB factors field into integer tuples."""
    if not isinstance(raw_factors, list):
        return None

    parsed: FactorList = []
    for entry in raw_factors:
        if not isinstance(entry, (list, tuple)) or len(entry) < 2:
            return None

        try:
            prime = int(str(entry[0]).strip())
            power = int(str(entry[1]).strip())
        except (TypeError, ValueError):
            return None

        parsed.append((prime, power))

    return parsed


def generate_continued_fractions(numerator: int, denominator: int) -> List[int]:
    """Generate continued fraction terms for numerator/denominator."""
    fractions: List[int] = []
    current_num = numerator
    current_den = denominator

    while current_den != 0:
        quotient = current_num // current_den
        fractions.append(quotient)
        current_num, current_den = current_den, current_num - quotient * current_den

    return fractions


def generate_convergents(fractions: Sequence[int]) -> List[Tuple[int, int]]:
    """Return convergents as (k, d_candidate) tuples."""
    numerator_prev, numerator_curr = 0, 1
    denominator_prev, denominator_curr = 1, 0
    convergents: List[Tuple[int, int]] = []

    for fraction in fractions:
        numerator_next = fraction * numerator_curr + numerator_prev
        denominator_next = fraction * denominator_curr + denominator_prev

        numerator_prev, numerator_curr = numerator_curr, numerator_next
        denominator_prev, denominator_curr = denominator_curr, denominator_next

        convergents.append((numerator_next, denominator_next))

    return convergents


def validate_wiener_candidate(
    e_value: int,
    n_value: int,
    k_value: int,
    d_value: int,
) -> Optional[Dict[str, int]]:
    """Validate a Wiener convergent and recover RSA parameters if valid."""
    if k_value == 0 or d_value == 0 or d_value % 2 == 0:
        return None

    if (e_value * d_value - 1) % k_value != 0:
        return None

    totient = (e_value * d_value - 1) // k_value
    s_value = n_value - totient + 1
    discriminant = s_value * s_value - 4 * n_value

    if discriminant < 0:
        return None

    sqrt_value = int(gmpy2.isqrt(discriminant))
    if sqrt_value * sqrt_value != discriminant:
        return None

    if (s_value + sqrt_value) % 2 != 0:
        return None

    p_value = (s_value + sqrt_value) // 2
    q_value = (s_value - sqrt_value) // 2
    if p_value <= 0 or q_value <= 0:
        return None
    if p_value * q_value != n_value:
        return None

    return {
        "d": d_value,
        "totient": totient,
        "p": p_value,
        "q": q_value,
        "k": k_value,
    }


def format_variable(value: Optional[int]) -> str:
    """Format long integers for compact table display."""
    if value is None:
        return "Not Set"

    value_text = str(value)
    if len(value_text) > 40:
        prefix = value_text[:20]
        suffix = value_text[-5:]
        return f"{prefix}...{suffix} (len={len(value_text)})"
    return value_text


class ToolkitUI:
    """Render dashboard components and handle interactive prompts."""

    def __init__(self, console: Console) -> None:
        self.console = console

    @staticmethod
    def clear_screen() -> None:
        """Clear terminal screen for a refreshed dashboard view."""
        os.system("cls" if os.name == "nt" else "clear")

    def info(self, message: str) -> None:
        """Print informational text with consistent style."""
        self.console.print(f"[bold #60a5fa][INFO][/bold #60a5fa] {message}")

    def success(self, message: str) -> None:
        """Print success text with consistent style."""
        self.console.print(f"[bold #34d399][OK][/bold #34d399] {message}")

    def warn(self, message: str) -> None:
        """Print warning text with consistent style."""
        self.console.print(f"[bold #fbbf24][WARN][/bold #fbbf24] {message}")

    def error(self, message: str) -> None:
        """Print error text with consistent style."""
        self.console.print(f"[bold #f87171][ERROR][/bold #f87171] {message}")

    def ask_text(self, prompt_text: str) -> str:
        """Ask for string input and return a stripped response."""
        return Prompt.ask(
            f"[bold #7dd3fc]{prompt_text}[/bold #7dd3fc]",
            console=self.console,
        ).strip()

    def ask_int(self, prompt_text: str) -> Tuple[Optional[int], Optional[str]]:
        """Ask for integer input and return value or user-facing error."""
        raw_value = self.ask_text(prompt_text)
        try:
            return int(raw_value), None
        except ValueError:
            return None, "Invalid integer input. Enter a whole number."

    def pause(self) -> None:
        """Pause until user confirms continuing."""
        self.console.print()
        Prompt.ask(
            "[bold #94a3b8]Press Enter to continue[/bold #94a3b8]",
            default="",
            console=self.console,
        )

    def render_dashboard(self, state: RSAState) -> None:
        """Render the full toolkit dashboard and menu."""
        self.clear_screen()
        self.console.print(self._build_header_panel())
        self.console.print()
        self.console.print(
            Columns(
                [self._build_state_panel(state), self._build_guide_panel()],
                equal=True,
                expand=True,
            )
        )
        self.console.print()
        self.console.print(self._build_menu_panel())
        self.console.print(
            "[bold #94a3b8]Tip:[/bold #94a3b8] "
            "Clear memory between challenges to avoid stale values."
        )

    def show_decoded_output(self, output_bytes: bytes) -> None:
        """Display UTF-8 plaintext if possible, otherwise raw bytes."""
        try:
            decoded_text = output_bytes.decode("utf-8")
            self.console.print(
                Panel(
                    Text(decoded_text, style="bold #22c55e"),
                    box=box.ROUNDED,
                    border_style="#22c55e",
                    title="[bold #22c55e]Output (UTF-8)[/bold #22c55e]",
                )
            )
        except UnicodeDecodeError:
            self.warn("Decrypted payload is not valid UTF-8.")
            self.console.print(
                Panel(
                    Text(str(output_bytes), style="bold #fbbf24"),
                    box=box.ROUNDED,
                    border_style="#fbbf24",
                    title="[bold #fbbf24]Output (Raw Bytes)[/bold #fbbf24]",
                )
            )

    def _build_header_panel(self) -> Panel:
        header_text = Text(HEADER_ART.strip("\n"), style="bold #e2e8f0")
        subtitle = "[bold #38bdf8]UJ CryptoBox | RSA CTF Sandbox[/bold #38bdf8]"
        return Panel(
            Align.center(header_text),
            box=box.ROUNDED,
            border_style="#22d3ee",
            title="[bold #f8fafc]UJ CryptoBox - RSA CTF Toolkit[/bold #f8fafc]",
            subtitle=subtitle,
            subtitle_align="center",
            padding=(1, 2),
        )

    def _build_state_panel(self, state: RSAState) -> Panel:
        table = Table(
            box=box.SIMPLE_HEAVY,
            expand=True,
            show_header=True,
            header_style="bold #93c5fd",
        )
        table.add_column("Variable", justify="center", no_wrap=True)
        table.add_column("Value", overflow="fold")

        for variable_name, value in state.iter_variables():
            value_style = "bold #34d399" if value is not None else "bold #f87171"
            table.add_row(
                Text(variable_name, style="bold #f8fafc"),
                Text(format_variable(value), style=value_style),
            )

        return Panel(
            table,
            box=box.ROUNDED,
            border_style="#64748b",
            title="[bold #f1f5f9]Session Memory[/bold #f1f5f9]",
        )

    def _build_guide_panel(self) -> Panel:
        guide_text = Text()
        guide_text.append("1) Set known values first: N, e, c.\n", style="bold #e2e8f0")
        guide_text.append("2) Use FactorDB to recover primes.\n", style="bold #cbd5e1")
        guide_text.append("3) Compute totient, then derive d.\n", style="bold #cbd5e1")
        guide_text.append(
            "4) Run decryption or attack modules.\n",
            style="bold #cbd5e1",
        )
        guide_text.append(
            "5) Use module 6 for exact-root low exponent cases.",
            style="bold #e2e8f0",
        )

        return Panel(
            guide_text,
            box=box.ROUNDED,
            border_style="#f472b6",
            title="[bold #f472b6]Operator Workflow[/bold #f472b6]",
        )

    def _build_menu_panel(self) -> Panel:
        table = Table(box=box.SIMPLE_HEAVY, expand=True, show_header=True)
        table.add_column("Option", justify="center", style="bold #fbbf24", no_wrap=True)
        table.add_column("Module", style="bold #e2e8f0")
        table.add_column("Purpose", style="#cbd5e1")

        for option, module_name, purpose in MENU_OPTIONS:
            table.add_row(option, module_name, purpose)

        return Panel(
            table,
            box=box.ROUNDED,
            border_style="#38bdf8",
            title="[bold #38bdf8]Interactive Modules[/bold #38bdf8]",
        )


class RSAToolkitApp:
    """Coordinate toolkit state, menu actions, and RSA modules."""

    def __init__(self, console: Optional[Console] = None) -> None:
        self.console = console or Console(highlight=False)
        self.ui = ToolkitUI(self.console)
        self.state = RSAState()
        self.actions: Dict[str, Callable[[], None]] = {
            "1": self.option_set_variable,
            "2": self.option_factordb,
            "3": self.option_calculate_totient,
            "4": self.option_calculate_d,
            "5": self.option_standard_decrypt,
            "6": self.option_nth_root_attack,
            "7": self.option_wiener_attack,
            "8": self.option_clear_memory,
            "9": self.option_exit,
        }

    def run(self) -> None:
        """Run the interactive toolkit loop until exit."""
        while True:
            self.sync_n_from_primes()
            self.ui.render_dashboard(self.state)
            choice = self.ui.ask_text("Choose module (1-9)")

            action = self.actions.get(choice)
            if action is None:
                self.ui.error("Invalid option. Choose a number from 1 to 9.")
                self.ui.pause()
                continue

            action()
            if choice != "9":
                self.ui.pause()

    def sync_n_from_primes(self) -> None:
        """Auto-calculate N from primes when memory is auto-managed."""
        p_value = self.state.p
        q_value = self.state.q
        r_value = self.state.r

        if p_value is None or q_value is None:
            if self.state.auto_n_from_primes and self.state.n is not None:
                self.state.n = None
                self.state.auto_n_from_primes = False
                self.ui.info(
                    "N was auto-cleared because p and q are no longer both set."
                )
            return

        target_n = p_value * q_value if r_value is None else p_value * q_value * r_value

        if self.state.n is None:
            self.state.n = target_n
            self.state.auto_n_from_primes = True
            self.ui.info("N has been auto-calculated from stored primes.")
            return

        if self.state.auto_n_from_primes and self.state.n != target_n:
            self.state.n = target_n
            self.ui.info("N has been auto-recalculated from updated primes.")

    def option_set_variable(self) -> None:
        """Set any supported RSA variable manually."""
        raw_name = self.ui.ask_text(
            "Variable to set (N, e, c, p, q, r, totient, d)"
        )
        variable_name = normalize_variable_name(raw_name)
        if variable_name is None:
            self.ui.error("Invalid variable name.")
            return

        value, error = self.ui.ask_int(f"Enter integer value for {variable_name}")
        if error:
            self.ui.error(error)
            return

        self.state.set_variable(variable_name, value)
        if variable_name == "N":
            self.state.auto_n_from_primes = False

        self.ui.success(f"{variable_name} saved successfully.")
        self.sync_n_from_primes()

    def option_factordb(self) -> None:
        """Query FactorDB and optionally persist discovered factors."""
        n_value = self.state.n
        if n_value is None:
            self.ui.error("N is not set. Set N before using FactorDB.")
            return

        endpoint = f"{FACTORDB_API_URL}?query={n_value}"
        try:
            with self.console.status(
                "[bold #7dd3fc]Querying FactorDB...[/bold #7dd3fc]",
                spinner="dots",
            ):
                response = requests.get(endpoint, timeout=20)
                response.raise_for_status()
                payload = response.json()
        except requests.RequestException as exc:
            self.ui.error(f"Failed to reach FactorDB: {exc}")
            return
        except ValueError:
            self.ui.error("FactorDB returned invalid JSON.")
            return

        status = str(payload.get("status", "")).strip()
        factors = parse_factordb_factors(payload.get("factors", []))

        self.ui.info(f"FactorDB status: {status}")

        if status == "P":
            self.ui.warn(f"Candidate p = {format_variable(n_value)}")
            should_save = Confirm.ask(
                "[bold #f9a8d4]N is prime. Save p = N?[/bold #f9a8d4]",
                default=False,
                console=self.console,
            )
            if should_save:
                self.state.p = n_value
                self.state.q = None
                self.state.r = None
                self.ui.success("p saved as N. q and r were reset.")
                self.sync_n_from_primes()
            else:
                self.ui.info("p was not saved.")
            return

        if factors is None:
            self.ui.error("Could not parse factors from FactorDB response.")
            return

        if status in ("FF", "CF") and len(factors) == 3:
            p_value = factors[0][0]
            q_value = factors[1][0]
            r_value = factors[2][0]

            self.ui.warn(f"Candidate p = {format_variable(p_value)}")
            self.ui.warn(f"Candidate q = {format_variable(q_value)}")
            self.ui.warn(f"Candidate r = {format_variable(r_value)}")

            should_save = Confirm.ask(
                "[bold #f9a8d4]Save factors as p, q, r?[/bold #f9a8d4]",
                default=False,
                console=self.console,
            )
            if should_save:
                self.state.p = p_value
                self.state.q = q_value
                self.state.r = r_value
                self.ui.success("p, q, and r saved successfully.")
                self.sync_n_from_primes()
            else:
                self.ui.info("Factors were not saved.")
            return

        if status in ("FF", "CF") and len(factors) == 1 and factors[0][1] == 2:
            p_value = factors[0][0]
            self.ui.warn(f"Candidate p = {format_variable(p_value)}")

            should_save = Confirm.ask(
                "[bold #f9a8d4]Detected N = p^2. Save p and q = p?[/bold #f9a8d4]",
                default=False,
                console=self.console,
            )
            if should_save:
                self.state.p = p_value
                self.state.q = p_value
                self.state.r = None
                self.ui.success("p saved and q set to p. r was reset.")
                self.sync_n_from_primes()
            else:
                self.ui.info("Values were not saved.")
            return

        if status in ("FF", "CF") and len(factors) == 2:
            p_value = factors[0][0]
            q_value = factors[1][0]

            self.ui.warn(f"Candidate p = {format_variable(p_value)}")
            self.ui.warn(f"Candidate q = {format_variable(q_value)}")

            should_save = Confirm.ask(
                "[bold #f9a8d4]Save factors as p and q?[/bold #f9a8d4]",
                default=False,
                console=self.console,
            )
            if should_save:
                self.state.p = p_value
                self.state.q = q_value
                self.state.r = None
                self.ui.success("p and q saved successfully.")
                self.sync_n_from_primes()
            else:
                self.ui.info("p and q were not saved.")
            return

        self.ui.error(
            "Unsupported factor layout. Expected one-prime, two-prime, "
            "three-prime, or p^2 format."
        )

    def option_calculate_totient(self) -> None:
        """Calculate and store totient based on current prime layout."""
        p_value = self.state.p
        q_value = self.state.q
        r_value = self.state.r

        if p_value is not None and q_value is not None and r_value is not None:
            self.state.totient = (p_value - 1) * (q_value - 1) * (r_value - 1)
            self.ui.success("totient calculated using p, q, and r.")
            self.ui.info(f"totient = {format_variable(self.state.totient)}")
            return

        if p_value is not None and q_value is not None and r_value is None:
            self.state.totient = (p_value - 1) * (q_value - 1)
            self.ui.success("totient calculated using p and q.")
            self.ui.info(f"totient = {format_variable(self.state.totient)}")
            return

        if p_value is not None and q_value is None and r_value is None:
            self.state.totient = p_value - 1
            self.ui.success("totient calculated using one-prime mode.")
            self.ui.info(f"totient = {format_variable(self.state.totient)}")
            return

        self.ui.error("Unsupported prime layout for automatic totient.")
        self.ui.info(
            "Set primes as p, p+q, or p+q+r. "
            "You can also set totient manually."
        )

    def option_calculate_d(self) -> None:
        """Calculate private exponent d from e and totient."""
        e_value = self.state.e
        totient_value = self.state.totient
        if e_value is None or totient_value is None:
            self.ui.error("e and totient must be set before calculating d.")
            return

        try:
            self.state.d = inverse(e_value, totient_value)
            self.ui.success("Private key d calculated and saved.")
            self.ui.info(f"d = {format_variable(self.state.d)}")
        except ValueError:
            self.ui.error(
                "Could not calculate d. "
                "e and totient are likely not coprime."
            )
        except Exception as exc:
            self.ui.error(f"Failed to calculate d: {exc}")

    def option_standard_decrypt(self) -> None:
        """Decrypt ciphertext with current c, d, and N values."""
        c_value = self.state.c
        d_value = self.state.d
        n_value = self.state.n
        if c_value is None or d_value is None or n_value is None:
            self.ui.error("c, d, and N must be set before decryption.")
            return

        try:
            message_value = pow(c_value, d_value, n_value)
            message_bytes = long_to_bytes(message_value)
            self.ui.show_decoded_output(message_bytes)
        except Exception as exc:
            self.ui.error(f"Decryption failed: {exc}")

    def option_nth_root_attack(self) -> None:
        """Attempt exact integer root attack against ciphertext c."""
        c_value = self.state.c
        if c_value is None:
            self.ui.error("c is not set. Set c before running this module.")
            return

        degree, error = self.ui.ask_int("Enter root degree (usually e)")
        if error:
            self.ui.error(error)
            return
        if degree is None or degree <= 1:
            self.ui.error("Root degree must be greater than 1.")
            return

        try:
            root_value, is_exact = gmpy2.iroot(c_value, degree)
            root_int = int(root_value)

            if is_exact:
                self.ui.success("Exact root found.")
                self.ui.show_decoded_output(long_to_bytes(root_int))
                return

            self.ui.warn("Root is not exact. Modulo likely wrapped around.")
            self.ui.info(f"Nearest integer root: {root_int}")
        except Exception as exc:
            self.ui.error(f"N-th root attack failed: {exc}")

    def option_wiener_attack(self) -> None:
        """Run Wiener attack and optionally decrypt with recovered key."""
        n_value = self.state.n
        e_value = self.state.e
        if n_value is None or e_value is None:
            self.ui.error("N and e must be set before running Wiener attack.")
            return

        fractions = generate_continued_fractions(e_value, n_value)
        convergents = generate_convergents(fractions)
        self.ui.info(
            f"Generated {len(convergents)} convergents. "
            "Testing candidate d values..."
        )

        for k_value, d_value in convergents:
            candidate = validate_wiener_candidate(e_value, n_value, k_value, d_value)
            if candidate is None:
                continue

            self.state.d = candidate["d"]
            self.state.totient = candidate["totient"]
            self.state.p = candidate["p"]
            self.state.q = candidate["q"]
            self.state.r = None

            self.ui.success("Wiener attack succeeded. Valid private key found.")
            self.ui.info(f"d = {format_variable(self.state.d)}")
            self.ui.info(f"totient = {format_variable(self.state.totient)}")
            self.ui.info(f"p = {format_variable(self.state.p)}")
            self.ui.info(f"q = {format_variable(self.state.q)}")
            self.sync_n_from_primes()

            if self.state.c is not None:
                self.ui.info(
                    "Ciphertext found in memory. Attempting decryption with "
                    "recovered d..."
                )
                self.option_standard_decrypt()
            return

        self.ui.warn("Wiener attack did not find a valid d for current N and e.")

    def option_clear_memory(self) -> None:
        """Reset all stored variables in session memory."""
        self.state.clear()
        self.ui.success("Memory cleared. All variables reset to Not Set.")

    def option_exit(self) -> None:
        """Exit toolkit process."""
        self.ui.info("Exiting UJ CryptoBox - RSA CTF Toolkit.")
        raise SystemExit(0)


def main() -> None:
    """Entrypoint for running the interactive RSA toolkit."""
    app = RSAToolkitApp()
    try:
        app.run()
    except KeyboardInterrupt:
        app.console.print()
        app.ui.warn("Interrupted by user. Exiting safely.")
        raise SystemExit(0)


if __name__ == "__main__":
    main()