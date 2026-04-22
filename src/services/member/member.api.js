import axiosClient from "../axiosClient";

export const memberApi = {
  memberPaymentToClub: async (payload) => {
    return axiosClient.post("/api/stripe/member-payment-intent", payload);
  },
  stripeOnboarding: async (payload) => {
    return axiosClient.post("/api/stripe/member-stripe-onboarding", payload);
  },
  memberReimbursementRequest: async (payload) => {
    return axiosClient.post(
      "/api/member/finance/reimbursement-request",
      payload,
    );
  },
  saveTransactionForDonation: async (payload) => {
    return axiosClient.post("/api/member/finance/save-donation", payload);
  },

  memberTransactions: async () => {
    return axiosClient.get("/api/member/finance/member-transactions");
  },

  getMemberDue: async (payload) => {
    return axiosClient.get("/api/member/finance/member-due");
  },

  getRecentMemberDue: async (payload) => {
    return axiosClient.get("/api/member/finance/recent-member-due");
  },

  payDue: async (payload) => {
    return axiosClient.post("/api/member/finance/pay-due", payload);
  },

  dueReceiptDownload: (payload) => {
    return axiosClient.post(
      "/api/member/finance/due-receipt-download",
      payload,
      {
        responseType: "blob", // For file download
      },
    );
  },

  getMemberStripeInfo: async () => {
    return axiosClient.get("/api/stripe/member-stripe-info");
  },

  getClubBudgetCategories: async () => {
    return axiosClient.get("/api/member/finance/club-budget-categories");
  },
};
