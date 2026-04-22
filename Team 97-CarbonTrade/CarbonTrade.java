import java.util.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class CarbonCreditSystem {

    // =========================================================================
    //  SECTION 1 — CONSTANTS & ENUMS
    // =========================================================================

    /**
     * Domain enum: each industry has a different emission multiplier.
     * Emission Limit = employees * multiplier * 10
     */
    enum Domain {
        MANUFACTURING (2.5, "Heavy industrial processes (steel, cement)"),
        ENERGY        (3.0, "Power generation — highest emitter class"),
        TRANSPORT     (1.8, "Road, rail, aviation logistics"),
        IT            (0.6, "Data centres and digital infrastructure"),
        AGRICULTURE   (1.2, "Farming, livestock, land use"),
        OTHER         (1.5, "General / unclassified sector");

        final double multiplier;
        final String description;
        Domain(double m, String d) { multiplier = m; description = d; }
    }

    static final double BASE_CREDIT_PRICE = 50.0;
    static final double MIN_PRICE         = 10.0;
    static final double MAX_PRICE         = 500.0;
    static final int    MAX_REQUESTS      = 3;

    // =========================================================================
    //  SECTION 2 — COMPANY MODEL
    // =========================================================================

    /**
     * Company is the core data object.
     * Implements Comparable so a PriorityQueue (Max-Heap) can rank companies:
     *   the company with MORE credits rises to the top = best seller.
     */
    static class Company implements Comparable<Company> {
        String companyId;
        String name;
        String passwordHash;   
        String salt;
        Domain domain;

        int    employees;
        double emissionLimit;
        double currentEmission;
        double credits;
        int    requestCount;   
        boolean isBlocked;

        // DSA: ArrayList stores 3 months of emission history for predictions
        ArrayList<Double> emissionHistory = new ArrayList<>();

        Company(String id, String name, String rawPassword, Domain domain, int employees) {
            this.companyId       = id;
            this.name            = name;
            this.domain          = domain;
            this.employees       = employees;
            this.salt            = generateSalt();
            this.passwordHash    = sha256(this.salt + rawPassword);

            // Domain formula: limit = employees x domain_multiplier x 10
            this.emissionLimit   = employees * domain.multiplier * 10;
            this.currentEmission = emissionLimit * 0.75;   // 75% of limit by default
            this.credits         = emissionLimit * 1.10;   // 10% buffer allotment
            this.requestCount    = 0;
            this.isBlocked       = false;

         
            emissionHistory.add(currentEmission * 0.88);
            emissionHistory.add(currentEmission * 0.94);
            emissionHistory.add(currentEmission);
        }

     
        @Override
        public int compareTo(Company other) {
            return Double.compare(other.credits, this.credits); // descending
        }

        // Credits safely available to sell (must keep >= 20% as reserve)
        double surplus() {
            return Math.max(0, credits - (credits * 0.20));
        }

        boolean checkPassword(String raw) {
            return passwordHash.equals(sha256(salt + raw));
        }

        // Green score for leaderboard — higher is greener
        double greenScore() {
            double overLimit = (currentEmission > emissionLimit)
                ? (currentEmission - emissionLimit) / emissionLimit : 0;
            return (credits / emissionLimit) - (requestCount * 0.05) - overLimit;
        }

        // 3-month moving average + 6% growth trend = predicted next emission
        double predictNextEmission() {
            if (emissionHistory.isEmpty()) return currentEmission;
            double sum = 0;
            for (double e : emissionHistory) sum += e;
            return (sum / emissionHistory.size()) * 1.06;
        }

        String status() {
            if (isBlocked)                               return "BLOCKED";
            if (currentEmission > emissionLimit * 1.5)  return "CRITICAL";
            if (currentEmission > emissionLimit)         return "OVER LIMIT";
            if (currentEmission > emissionLimit * 0.9)  return "WARNING";
            return "COMPLIANT";
        }
    }

    // =========================================================================
    //  SECTION 3 — TRANSACTION MODEL (SHA-256 Audit Hash)
    // =========================================================================

    /**
     * Every trade creates a Transaction appended to the ledger ArrayList.
     *
     * auditHash = SHA-256( txId + sellerId + buyerId + amount + price + timestamp + prevHash )
     *
     * Chaining each hash to the previous one creates a tamper-evident ledger:
     * if any old record is changed, ALL subsequent hashes break — like a blockchain.
     */
    static class Transaction {
        int    txId;
        String sellerId, buyerId;
        double amount, pricePerCredit;
        String timestamp;
        String auditHash;
        String prevHash;

        Transaction(int txId, String sellerId, String buyerId,
                    double amount, double price, String prevHash) {
            this.txId           = txId;
            this.sellerId       = sellerId;
            this.buyerId        = buyerId;
            this.amount         = amount;
            this.pricePerCredit = price;
            this.timestamp      = new Date().toString();
            this.prevHash       = prevHash;
            String raw = txId + sellerId + buyerId + amount + price + timestamp + prevHash;
            this.auditHash = sha256(raw);
        }
    }

    // =========================================================================
    //  SECTION 4 — IN-MEMORY DSA STORAGE
    // =========================================================================

    //  companyMap  -> HashMap<String, Company>
    //                 O(1) lookup by companyId, O(1) insert, O(1) duplicate check
    //
    //  companyList -> ArrayList<Company>
    //                 ordered list for iteration, display, leaderboard sorting
    //
    //  nameIndex   -> HashMap<String, Boolean>
    //                 O(1) check: "is this name already taken?"
    //
    //  ledger      -> ArrayList<Transaction>
    //                 append-only ordered audit trail (each record is SHA-256 hashed)

    static HashMap<String, Company>  companyMap  = new HashMap<>();
    static ArrayList<Company>        companyList = new ArrayList<>();
    static HashMap<String, Boolean>  nameIndex   = new HashMap<>();
    static ArrayList<Transaction>    ledger      = new ArrayList<>();

    static int     nextCompanyNum = 1;
    static int     nextTxId       = 1;
    static Company currentUser    = null;   // the logged-in company (null = nobody)

    // =========================================================================
    //  SECTION 5 — SECURITY UTILITIES
    // =========================================================================

    // Compute SHA-256 of any string -> 64-character hex string
    static String sha256(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] bytes = md.digest(input.getBytes());
            StringBuilder sb = new StringBuilder();
            for (byte b : bytes) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            return "HASH_ERROR";
        }
    }

    // Random 8-char salt for password hashing
    static String generateSalt() {
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        Random rng = new Random();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 8; i++) sb.append(chars.charAt(rng.nextInt(chars.length())));
        return sb.toString();
    }

    // Return the hash of the last ledger entry (chains transactions together)
    static String lastHash() {
        if (ledger.isEmpty()) return "GENESIS";
        return ledger.get(ledger.size() - 1).auditHash;
    }

    // =========================================================================
    //  SECTION 6 — DYNAMIC PRICING
    // =========================================================================

    /**
     * Price = BASE_PRICE * (demand / supply)
     * Clamped between MIN_PRICE and MAX_PRICE.
     *
     * High demand + low supply  -> price rises (discourages wasteful buying)
     * Low demand + high supply  -> price falls (rewards green sellers)
     */
    static double dynamicPrice(double demand, double supply) {
        if (supply <= 0) return MAX_PRICE;
        double price = BASE_CREDIT_PRICE * (demand / supply);
        return Math.max(MIN_PRICE, Math.min(MAX_PRICE, price));
    }

    // =========================================================================
    //  SECTION 7 — VALIDATION PIPELINE (5 stages)
    // =========================================================================

    /**
     * Returns null if trade is allowed, or a block reason string.
     *
     * Stage 1: Blocked account check
     * Stage 2: Max 3 buy-requests per cycle
     * Stage 3: Buyer emission must be < 1.5x their limit
     * Stage 4: Buy amount must be <= 50% of buyer's emission limit
     * Stage 5: Seller must keep >= 20% of their credits after the sale
     */
    static String validate(Company buyer, Company seller, double requested) {
        if (buyer.isBlocked)
            return "Stage 1 FAIL: Your account is BLOCKED.";
        if (buyer.requestCount >= MAX_REQUESTS)
            return "Stage 2 FAIL: Max " + MAX_REQUESTS + " buy requests per cycle reached.";
        if (buyer.currentEmission > buyer.emissionLimit * 1.5)
            return "Stage 3 FAIL: Your emission exceeds 1.5x your limit. Trade rejected.";
        if (requested > buyer.emissionLimit * 0.50)
            return "Stage 4 FAIL: Cannot buy more than 50% of your emission limit at once.";
        if (seller.credits - requested < seller.credits * 0.20)
            return "Stage 5 FAIL: Seller must keep >=20% reserve. Max they can sell: "
                   + String.format("%.2f", seller.surplus());
        if (seller.credits < requested)
            return "Stage 5 FAIL: Seller only has " + String.format("%.2f", seller.credits)
                   + " credits.";
        if (buyer.companyId.equals(seller.companyId))
            return "Cannot trade with yourself!";
        return null; // all stages passed
    }

    // =========================================================================
    //  SECTION 8 — MATCHING ENGINE (Max-Heap PriorityQueue)
    // =========================================================================

    /**
     * DSA: PriorityQueue<Company> is used as a Max-Heap.
     *
     * HOW IT WORKS:
     *   1. All eligible sellers are inserted into the heap — O(log n) each.
     *      The heap self-organises so the richest seller is always at the top.
     *   2. poll() removes the top (richest) seller in O(log n).
     *
     * MATCHING PRIORITY:
     *   Same-domain sellers are preferred (they understand the buyer's context).
     *   If no same-domain match, fallback to the overall richest seller.
     *
     * WHY HEAP OVER LINEAR SEARCH?
     *   Linear scan = O(n) every time.
     *   Max-heap = O(log n) insert + O(log n) poll — far better at scale.
     */
    static Company findBestSeller(Company buyer, double needed) {
        // Build max-heap of all eligible sellers
        PriorityQueue<Company> heap = new PriorityQueue<>();
        for (Company c : companyList) {
            if (!c.companyId.equals(buyer.companyId) && !c.isBlocked && c.surplus() >= needed) {
                heap.add(c); // O(log n)
            }
        }
        if (heap.isEmpty()) return null;

        // Pass 1: same-domain preference
        List<Company> skipped = new ArrayList<>();
        while (!heap.isEmpty()) {
            Company top = heap.poll(); // O(log n) — always removes richest
            if (top.domain == buyer.domain) return top;
            skipped.add(top);
        }

        // Pass 2: no same-domain match — richest available seller
        return skipped.isEmpty() ? null : skipped.get(0);
    }

    // =========================================================================
    //  SECTION 9 — PREDICTIVE WARNING ENGINE
    // =========================================================================

    /**
     * Uses a 3-month moving average + 6% trend to predict next month's emission.
     * If the prediction > emission limit, a warning box is shown on the dashboard.
     *
     * DSA: emissionHistory is an ArrayList — O(1) append, O(n) average calculation.
     */
    static void checkPredictiveWarning(Company c) {
        double predicted = c.predictNextEmission();
        if (predicted > c.emissionLimit) {
            double excess = predicted - c.emissionLimit;
            int creditsNeeded = (int) Math.ceil(excess / 10.0);
            System.out.println();
            System.out.println("  +------------------------------------------------------+");
            System.out.println("  |  ** PREDICTIVE WARNING — AI EMISSION FORECAST **    |");
            System.out.println("  +------------------------------------------------------+");
            System.out.printf ("  |  3-month avg            : %8.1f t               |%n", c.currentEmission);
            System.out.printf ("  |  Predicted next month   : %8.1f t (6%% growth)   |%n", predicted);
            System.out.printf ("  |  Your emission limit    : %8.1f t               |%n", c.emissionLimit);
            System.out.printf ("  |  Expected overshoot     : %8.1f t               |%n", excess);
            System.out.printf ("  |  Recommended credits    : buy %4d NOW            |%n", creditsNeeded);
            System.out.println("  +------------------------------------------------------+");
        }
    }

    // =========================================================================
    //  SECTION 10 — CONSOLE UI HELPERS
    // =========================================================================

    static void printBanner() {
        System.out.println();
        System.out.println("  +============================================================+");
        System.out.println("  |    *** CARBON CREDIT TRADING SYSTEM v2.0 ***              |");
        System.out.println("  |    Pure Java  *  DSA  *  SHA-256  *  No Database          |");
        System.out.println("  +============================================================+");
        System.out.println();
    }

    static void printAuthMenu() {
        System.out.println("  +--------------------------------------+");
        System.out.println("  |         WELCOME — PLEASE             |");
        System.out.println("  +--------------------------------------+");
        System.out.println("  |  1  Register New Company             |");
        System.out.println("  |  2  Login to Your Account            |");
        System.out.println("  |  0  Exit                             |");
        System.out.println("  +--------------------------------------+");
        System.out.print("  >> Choice: ");
    }

    static void printMainMenu(String label) {
        System.out.println();
        System.out.println("  +====================================================+");
        System.out.printf ("  |  Logged in: %-38s|%n", label);
        System.out.println("  +====================================================+");
        System.out.println("  |  1  My Dashboard  (credits, warnings)              |");
        System.out.println("  |  2  View All Companies                             |");
        System.out.println("  |  3  Search Company by ID                           |");
        System.out.println("  |  4  Trade Credits  (manual — I pick seller)        |");
        System.out.println("  |  5  Auto-Match Trade  (Heap Engine finds seller)   |");
        System.out.println("  |  6  Audit Ledger  (SHA-256 hashed transactions)    |");
        System.out.println("  |  7  Green Leaderboard                              |");
        System.out.println("  |  8  Register Another Company                       |");
        System.out.println("  |  L  Logout                                         |");
        System.out.println("  |  0  Exit                                           |");
        System.out.println("  +====================================================+");
        System.out.print("  >> Choice: ");
    }

    static void line()        { System.out.println("  " + "-".repeat(60)); }
    static void ok(String m)  { System.out.println("  [OK]   " + m); }
    static void err(String m) { System.out.println("  [ERR]  " + m); }
    static void info(String m){ System.out.println("  [INFO] " + m); }
    static void warn(String m){ System.out.println("  [WARN] " + m); }

    // =========================================================================
    //  SECTION 11 — REGISTER COMPANY
    // =========================================================================

    static void registerCompany(Scanner sc) {
        System.out.println();
        line();
        System.out.println("  REGISTER NEW COMPANY");
        line();

        System.out.print("  Company Name       : ");
        String name = sc.nextLine().trim();
        if (name.isEmpty()) { err("Name cannot be empty."); return; }

        // DSA: HashMap O(1) check — prevent duplicate names
        if (nameIndex.containsKey(name.toLowerCase())) {
            err("\"" + name + "\" already exists. All company names must be unique.");
            return;
        }

        // Show domain menu
        System.out.println();
        System.out.println("  +-- Choose Domain -------------------------------------------------------+");
        Domain[] domains = Domain.values();
        for (int i = 0; i < domains.length; i++) {
            System.out.printf("  |  %d  %-14s  x%.1f  %s%n",
                i+1, domains[i].name(), domains[i].multiplier, domains[i].description);
        }
        System.out.println("  +------------------------------------------------------------------------+");
        System.out.print("  Select (1-" + domains.length + ")    : ");

        Domain domain;
        try {
            int ch = Integer.parseInt(sc.nextLine().trim()) - 1;
            if (ch < 0 || ch >= domains.length) { err("Invalid choice."); return; }
            domain = domains[ch];
        } catch (NumberFormatException e) { err("Enter a number."); return; }

        System.out.print("  Number of Employees: ");
        int employees;
        try { employees = Integer.parseInt(sc.nextLine().trim()); }
        catch (NumberFormatException e) { err("Invalid number."); return; }
        if (employees <= 0) { err("Employees must be > 0."); return; }

        System.out.print("  Set Password       : ");
        String password = sc.nextLine().trim();
        if (password.length() < 4) { err("Password must be at least 4 characters."); return; }

        // Auto-generate unique company ID: C001, C002, ...
        String cid = String.format("C%03d", nextCompanyNum++);
        while (companyMap.containsKey(cid)) cid = String.format("C%03d", nextCompanyNum++);

        Company c = new Company(cid, name, password, domain, employees);

        // DSA: Insert into HashMap O(1) and ArrayList O(1) amortised
        companyMap.put(cid, c);
        companyList.add(c);
        nameIndex.put(name.toLowerCase(), true);

        System.out.println();
        ok("Company registered!");
        System.out.println("  +---------------------------------------------------+");
        System.out.printf ("  |  Your Company ID  : %-29s|%n", cid);
        System.out.printf ("  |  Domain           : %-29s|%n", domain.name());
        System.out.printf ("  |  Emission Formula : %d emp x %.1f x 10 = %.0f t%n",
                           employees, domain.multiplier, c.emissionLimit);
        System.out.printf ("  |  Credits Allotted : %-29s|%n",
                           String.format("%.2f (limit x 1.10 buffer)", c.credits));
        System.out.printf ("  |  Password stored  : SHA-256 hash — never plain    |%n");
        System.out.println("  +---------------------------------------------------+");
        info("SAVE your ID: [" + cid + "] — you need it to login!");
        line();
    }

    // =========================================================================
    //  SECTION 12 — LOGIN
    // =========================================================================

    static boolean login(Scanner sc) {
        System.out.println();
        line();
        System.out.println("  LOGIN");
        line();

        System.out.print("  Company ID : ");
        String id = sc.nextLine().trim().toUpperCase();

        // DSA: HashMap O(1) lookup
        Company c = companyMap.get(id);
        if (c == null) { err("No company found with ID: " + id); return false; }

        System.out.print("  Password   : ");
        String pwd = sc.nextLine().trim();

        if (!c.checkPassword(pwd)) { err("Incorrect password."); return false; }
        if (c.isBlocked)           { err("Account is BLOCKED."); return false; }

        currentUser = c;
        System.out.println();
        ok("Welcome back, " + c.name + "! Login successful.");
        line();
        return true;
    }

    // =========================================================================
    //  SECTION 13 — DASHBOARD
    // =========================================================================

    static void showDashboard() {
        Company c = currentUser;
        System.out.println();
        System.out.println("  +============================================================+");
        System.out.printf ("  |  DASHBOARD — %-47s|%n", c.name);
        System.out.println("  +============================================================+");
        System.out.printf ("  |  Company ID       : %-40s|%n", c.companyId);
        System.out.printf ("  |  Domain           : %-40s|%n", c.domain.name());
        System.out.printf ("  |  Employees        : %-40s|%n", c.employees);
        System.out.println("  +------------------------------------------------------------+");
        System.out.printf ("  |  Credits Held     : %-40s|%n", String.format("%.2f", c.credits));
        System.out.printf ("  |  Surplus (sellable): %-39s|%n", String.format("%.2f", c.surplus()));
        System.out.printf ("  |  Buy Requests     : %-40s|%n",
                           c.requestCount + " / " + MAX_REQUESTS + " used this cycle");
        System.out.println("  +------------------------------------------------------------+");
        System.out.printf ("  |  Current Emission : %-40s|%n",
                           String.format("%.1f t  /  %.1f t limit", c.currentEmission, c.emissionLimit));
        System.out.printf ("  |  Status           : %-40s|%n", c.status());
        System.out.printf ("  |  Green Score      : %-40s|%n", String.format("%.3f", c.greenScore()));
        System.out.println("  +============================================================+");

        checkPredictiveWarning(c);
        System.out.println();
    }

    // =========================================================================
    //  SECTION 14 — VIEW ALL COMPANIES
    // =========================================================================

    static void viewAllCompanies() {
        System.out.println();
        line();
        System.out.printf("  ALL COMPANIES  (%d registered)%n", companyList.size());
        line();
        if (companyList.isEmpty()) { info("No companies yet."); return; }

        System.out.printf("  %-5s  %-18s  %-13s  %9s  %9s  %8s%n",
                "ID", "Name", "Domain", "Credits", "Status", "Score");
        System.out.println("  " + "-".repeat(68));

        // DSA: O(n) iteration over ArrayList
        for (Company c : companyList) {
            System.out.printf("  %-5s  %-18s  %-13s  %9.2f  %9s  %8.3f%n",
                    c.companyId, c.name, c.domain.name(),
                    c.credits, c.status(), c.greenScore());
        }
        line();
    }

    // =========================================================================
    //  SECTION 15 — SEARCH BY ID
    // =========================================================================

    static void searchById(Scanner sc) {
        System.out.println();
        line();
        System.out.println("  SEARCH COMPANY BY ID");
        line();
        System.out.print("  Enter Company ID: ");
        String id = sc.nextLine().trim().toUpperCase();

        // DSA: HashMap O(1) lookup
        Company c = companyMap.get(id);
        if (c == null) { err("No company found with ID: " + id); return; }

        System.out.println();
        System.out.println("  +---------------------------------------------------+");
        System.out.printf ("  |  ID              : %-30s|%n", c.companyId);
        System.out.printf ("  |  Name            : %-30s|%n", c.name);
        System.out.printf ("  |  Domain          : %-30s|%n", c.domain.name());
        System.out.printf ("  |  Employees       : %-30s|%n", c.employees);
        System.out.printf ("  |  Credits         : %-30s|%n", String.format("%.2f", c.credits));
        System.out.printf ("  |  Surplus         : %-30s|%n", String.format("%.2f (can sell)", c.surplus()));
        System.out.printf ("  |  Emission        : %-30s|%n",
                           String.format("%.1f t / %.1f t", c.currentEmission, c.emissionLimit));
        System.out.printf ("  |  Status          : %-30s|%n", c.status());
        System.out.printf ("  |  Green Score     : %-30s|%n", String.format("%.3f", c.greenScore()));
        System.out.println("  +---------------------------------------------------+");
        line();
    }

    // =========================================================================
    //  SECTION 16 — MANUAL TRADE
    // =========================================================================

    static void manualTrade(Scanner sc) {
        System.out.println();
        line();
        System.out.println("  TRADE CREDITS — MANUAL  (you choose the seller)");
        line();

        Company buyer = currentUser;
        System.out.print("  Seller Company ID : ");
        String sid = sc.nextLine().trim().toUpperCase();

        Company seller = companyMap.get(sid); // O(1)
        if (seller == null) { err("Seller ID not found."); return; }

        System.out.printf("  Seller: %s  |  Available: %.2f credits%n",
                          seller.name, seller.surplus());
        System.out.print("  Credits to buy    : ");
        double amount;
        try { amount = Double.parseDouble(sc.nextLine().trim()); }
        catch (NumberFormatException e) { err("Invalid number."); return; }

        executeTrade(buyer, seller, amount);
    }

    // =========================================================================
    //  SECTION 17 — AUTO-MATCH TRADE
    // =========================================================================

    static void autoMatchTrade(Scanner sc) {
        System.out.println();
        line();
        System.out.println("  AUTO-MATCH TRADE  (PriorityQueue Max-Heap Engine)");
        line();

        Company buyer = currentUser;
        System.out.print("  Credits you want  : ");
        double amount;
        try { amount = Double.parseDouble(sc.nextLine().trim()); }
        catch (NumberFormatException e) { err("Invalid number."); return; }

        info("Building Max-Heap of eligible sellers...");
        info("Heap preference: same-domain seller (priority) -> richest available");

        Company seller = findBestSeller(buyer, amount);
        if (seller == null) {
            err("No eligible seller found with at least " + amount + " credits to sell.");
            return;
        }

        boolean sameDomain = seller.domain == buyer.domain;
        ok("Best seller found: " + seller.name + " (" + seller.companyId + ")"
           + (sameDomain ? "  [SAME DOMAIN - priority match!]" : "  [cross-domain]"));

        executeTrade(buyer, seller, amount);
    }

    // =========================================================================
    //  SECTION 18 — EXECUTE TRADE (shared by manual and auto-match)
    // =========================================================================

    /**
     * Runs validation pipeline -> prices the trade -> updates company credits
     * -> appends a SHA-256 hashed Transaction to the ledger.
     *
     * KEY DSA POINT:
     *   companyMap and companyList both hold REFERENCES to the same Company objects.
     *   When we do seller.credits -= amount here, the change is automatically
     *   visible in BOTH the HashMap and the ArrayList — no sync needed.
     */
    static void executeTrade(Company buyer, Company seller, double amount) {
        // Run 5-stage validation
        String blocked = validate(buyer, seller, amount);
        if (blocked != null) { err(blocked); return; }

        // Dynamic price based on supply/demand
        double price = dynamicPrice(amount, seller.surplus());

        // Execute — mutate the shared Company objects directly
        seller.credits -= amount;
        buyer.credits  += amount;
        buyer.requestCount++;

        // Check penalty levels
        applyPenalties(buyer);

        // Create a SHA-256-hashed transaction and append to ledger (O(1))
        Transaction tx = new Transaction(nextTxId++, seller.companyId,
                                         buyer.companyId, amount, price, lastHash());
        ledger.add(tx); // DSA: ArrayList O(1) amortised append

        System.out.println();
        ok("TRADE EXECUTED SUCCESSFULLY!");
        System.out.println("  +------------------------------------------------------+");
        System.out.printf ("  |  TX ID        : %-35s|%n", "TX-" + String.format("%04d", tx.txId));
        System.out.printf ("  |  Seller       : %-35s|%n", seller.name);
        System.out.printf ("  |  Buyer        : %-35s|%n", buyer.name);
        System.out.printf ("  |  Credits      : %-35s|%n", String.format("%.2f", amount));
        System.out.printf ("  |  Price/credit : Rs. %-31s|%n", String.format("%.2f", price));
        System.out.printf ("  |  Total Value  : Rs. %-31s|%n", String.format("%.2f", amount * price));
        System.out.printf ("  |  Audit Hash   : %-35s|%n", tx.auditHash.substring(0, 20) + "...");
        System.out.println("  +------------------------------------------------------+");
        line();
    }

    // Penalty system: WARNING -> FINE -> BLOCK based on buy count and emissions
    static void applyPenalties(Company c) {
        if (c.currentEmission > c.emissionLimit * 2.0) {
            c.isBlocked = true;
            warn("PENALTY LV3 - ACCOUNT BLOCKED: Emission > 2x limit.");
        } else if (c.requestCount >= 3) {
            double fine = (c.requestCount - 2) * 10.0;
            c.credits = Math.max(0, c.credits - fine);
            warn("PENALTY LV2 - FINE: " + fine + " credits deducted for excessive buying.");
        } else if (c.requestCount >= 2) {
            warn("PENALTY LV1 - WARNING: " + c.requestCount + " buy requests used. Max is " + MAX_REQUESTS + ".");
        }
    }

    // =========================================================================
    //  SECTION 19 — AUDIT LEDGER
    // =========================================================================

    static void viewLedger() {
        System.out.println();
        line();
        System.out.printf("  IMMUTABLE AUDIT LEDGER  (%d transactions)%n", ledger.size());
        System.out.println("  Each record is SHA-256 hashed and chained to the previous.");
        line();

        if (ledger.isEmpty()) { info("No transactions yet."); return; }

        System.out.printf("  %-7s  %-6s  %-6s  %9s  %10s  %-22s%n",
                "TX-ID", "Seller", "Buyer", "Credits", "Price/unit", "Hash (first 22 chars)");
        System.out.println("  " + "-".repeat(70));

        // DSA: O(n) iteration over ArrayList
        for (Transaction t : ledger) {
            System.out.printf("  TX-%04d  %-6s  %-6s  %9.2f  Rs.%-7.2f  %s...%n",
                    t.txId, t.sellerId, t.buyerId,
                    t.amount, t.pricePerCredit, t.auditHash.substring(0, 22));
        }
        line();
        info("VERIFY: Recompute SHA-256(txId+sellerId+buyerId+amount+price+timestamp+prevHash)");
        info("If any hash mismatches -> ledger has been tampered with.");
        line();
    }

    // =========================================================================
    //  SECTION 20 — GREEN LEADERBOARD
    // =========================================================================

    /**
     * DSA: copies the ArrayList, then sorts it with Collections.sort() in O(n log n).
     * Score = (credits/emissionLimit) - (requestCount x 0.05) - overLimit penalty.
     * Higher score = greener company.
     */
    static void showLeaderboard() {
        System.out.println();
        line();
        System.out.println("  GREEN LEADERBOARD");
        System.out.println("  Score = (credits/limit) - (requests x 0.05) - overLimit penalty");
        line();

        if (companyList.isEmpty()) { info("No companies to rank."); return; }

        // DSA: copy ArrayList then sort — O(n log n)
        List<Company> ranked = new ArrayList<>(companyList);
        ranked.sort((a, b) -> Double.compare(b.greenScore(), a.greenScore()));

        System.out.printf("  %-4s  %-18s  %-13s  %9s  %9s  %8s%n",
                "Rank", "Company", "Domain", "Credits", "Status", "Score");
        System.out.println("  " + "-".repeat(68));

        int rank = 1;
        for (Company c : ranked) {
            String medal = rank == 1 ? "[1st]" : rank == 2 ? "[2nd]" : rank == 3 ? "[3rd]" : "     ";
            String you   = (currentUser != null && c.companyId.equals(currentUser.companyId))
                           ? " <- YOU" : "";
            System.out.printf("  %s %-18s  %-13s  %9.2f  %9s  %8.3f%s%n",
                    medal, c.name, c.domain.name(),
                    c.credits, c.status(), c.greenScore(), you);
            rank++;
        }
        line();
    }

 

    static void loadSampleData() {
        String[]   names     = {"Tata Steel Ltd", "Solar Grid India", "Metro Railways",
                                "TechCloud IT",   "AgroFarm Co."};
        String[]   pwds      = {"tata123", "solar1", "metro9", "tech55", "agro77"};
        Domain[]   doms      = {Domain.MANUFACTURING, Domain.ENERGY, Domain.TRANSPORT,
                                Domain.IT, Domain.AGRICULTURE};
        int[]      emps      = {5000, 2000, 3500, 1200, 800};

        for (int i = 0; i < names.length; i++) {
            String cid = String.format("C%03d", nextCompanyNum++);
            Company c = new Company(cid, names[i], pwds[i], doms[i], emps[i]);
            companyMap.put(cid, c);
            companyList.add(c);
            nameIndex.put(names[i].toLowerCase(), true);
        }

        info("5 sample companies loaded: C001 to C005");
        System.out.println("  +-------------------------------------------+");
        System.out.println("  |  ID    Name                Password        |");
        System.out.println("  +-------------------------------------------+");
        System.out.println("  |  C001  Tata Steel Ltd      tata123         |");
        System.out.println("  |  C002  Solar Grid India    solar1          |");
        System.out.println("  |  C003  Metro Railways      metro9          |");
        System.out.println("  |  C004  TechCloud IT        tech55          |");
        System.out.println("  |  C005  AgroFarm Co.        agro77          |");
        System.out.println("  +-------------------------------------------+");
        System.out.println();
    }



    public static void main(String[] args) {
        Scanner sc      = new Scanner(System.in);
        boolean running = true;

        printBanner();
        loadSampleData();

        while (running) {

            if (currentUser == null) {
                printAuthMenu();
                String choice = sc.nextLine().trim();
                switch (choice) {
                    case "1" -> registerCompany(sc);
                    case "2" -> login(sc);
                    case "0" -> running = false;
                    default  -> err("Enter 1, 2, or 0.");
                }

            } else {
                printMainMenu(currentUser.name + " [" + currentUser.companyId + "]");
                String choice = sc.nextLine().trim().toUpperCase();
                switch (choice) {
                    case "1" -> showDashboard();
                    case "2" -> viewAllCompanies();
                    case "3" -> searchById(sc);
                    case "4" -> manualTrade(sc);
                    case "5" -> autoMatchTrade(sc);
                    case "6" -> viewLedger();
                    case "7" -> showLeaderboard();
                    case "8" -> registerCompany(sc);
                    case "L" -> {
                        ok("Logged out. Goodbye, " + currentUser.name + "!");
                        currentUser = null;
                    }
                    case "0" -> running = false;
                    default  -> err("Invalid option. Choose 1-8, L, or 0.");
                }
            }
        }

        System.out.println();
        System.out.println("  Thank you for trading green. Goodbye!");
        System.out.println();
        sc.close();
    }
}