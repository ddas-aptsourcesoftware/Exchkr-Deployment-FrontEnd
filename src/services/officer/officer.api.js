import axiosClient from "../axiosClient";

export const officerApi = {
  addMember: async (payload) => {
    return axiosClient.post("/api/officer/members", payload);
  },

  fetchMembers: async () => {
    return axiosClient.get("/api/officer/members");
  },

  memberCount: async () => {
    return axiosClient.get("/api/officer/members/count");
  },

  bankConnectionStatus: async () => {
    return axiosClient.get("/api/plaid/status");
  },

  generateLinkToken: async (payload) => {
    return axiosClient.post("/api/plaid/link-token", null);
  },

  exchangePublicToken: async (payload) => {
    return axiosClient.post("/api/plaid/exchange-token", payload);
  },

  getBankBalance: async () => {
    return axiosClient.get("/api/plaid/balance");
  },

  changeDefaultAccount: async (payload) => {
    return axiosClient.patch("/api/plaid/default-account", payload);
  },

  disconnectBank: async () => {
    return axiosClient.post("/api/plaid/unlink");
  },

  reactivateBank: async () => {
    return axiosClient.post("/api/plaid/reactivate");
  },

  stripeOnboarding: async (payload) => {
    return axiosClient.post("/api/stripe/account-onboarding", payload);
  },

  getClubBalance: async () => {
    return axiosClient.get("/api/stripe/stripe-balance");
  },
  clubPaymentToMember: async (payload) => {
    return axiosClient.post("/api/stripe/club-payment-intent", payload);
  },
  reimbursementRequestList: async () => {
    return axiosClient.get("/api/club/finance/reimbursement-request-list");
  },

  reimbursementRequestReject: async (payload) => {
    return axiosClient.post(
      "/api/club/finance/reimbursement-request-reject",
      payload,
    );
  },
  reimbursementRequestApprove: async (payload) => {
    return axiosClient.post(
      "/api/club/finance/reimbursement-request-approve",
      payload,
    );
  },
  reimbursementReceiptDownload: (payload) => {
    return axiosClient.post(
      "/api/club/finance/reimbursement-receipt-download",
      payload,
      {
        responseType: "blob", // For file download
      },
    );
  },
  saveTransaction: async (payload) => {
    return axiosClient.post("/api/club/finance/record-success", payload);
  },

  getTransactionHistory: async ({ page = 0, size = 10 }) => {
    return axiosClient.get("/api/club/finance/history", {
      params: {
        page,
        size,
      },
    });
  },

  downloadTransactionHistoryPdf: async (payload) => {
    return axiosClient.post("/api/club/finance/download-trans-pdf", payload, {
      responseType: "blob",
    });
  },
  addTransaction: async (payload) => {
    return axiosClient.post("/api/club/finance/record-success", payload);
  },

  createInvoiceAndDue: async (payload) => {
    return axiosClient.post("/api/club/finance/create-invoice", payload);
  },

  getDuesList: async ({ page = 0, size = 8 }) => {
    return axiosClient.get("/api/club/finance/member-dues", {
      params: {
        page,
        size,
      },
      withCredentials: true,
    });
  },

  getDuesSummary: async () => {
    return axiosClient.get("/api/club/finance/dues-summary");
  },

  getFinanceSummary: async () => {
    return axiosClient.get("/api/club/finance/finance-summary");
  },

  sentDueReminder: async (payload) => {
    return axiosClient.post("/api/club/finance/member-dues/remind", payload);
  },

  sentDueReminders: async (payload) => {
    return axiosClient.post(
      "/api/club/finance/member-dues/remind-bulk",
      payload,
    );
  },

  getPendingActions: async () => {
    return axiosClient.get("/api/club/finance/pending-actions");
  },

  getClubStripeInfo: async () => {
    return axiosClient.get("/api/stripe/club-stripe-info");
  },

  getRecentActivity: async () => {
    return axiosClient.get("/api/club/finance/recent-activity");
  },
  addMembersCSV: async (payload) => {
    return axiosClient.post("/api/officer/members/csv", payload);
  },

  getSpendingCategory: async () => {
    return axiosClient.get("/api/club/finance/spending-by-category");
  },

  getMonthlySpending: async () => {
    return axiosClient.get("/api/club/finance/monthly-spending");
  },

  addBudget: async (payload) => {
    return axiosClient.post("/api/club/finance/budget-setup", payload);
  },

  updateBudget: async (payload) => {
    return axiosClient.patch("/api/club/finance/budget", payload);
  },

  getClubBudgetSummary: async () => {
    return axiosClient.get("/api/club/finance/budget-summary");
  },

  downloadDuesListPdf: async (payload) => {
    return axiosClient.post("/api/club/finance/download-dues-pdf", payload, {
      responseType: "blob",
    });
  },

  budgetCategories: {
    create: async (payload) => {
      return axiosClient.post("/api/club/finance/budget-categories", payload);
    },

    getAll: async () => {
      return axiosClient.get("/api/club/finance/budget-categories");
    },
  },
};
