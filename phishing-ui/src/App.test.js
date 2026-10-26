import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { getIncidents, scanInbox } from "./api";
import App from "./App";

jest.mock("./api", () => ({
  getIncidents: jest.fn(),
  scanInbox: jest.fn(),
}));

test("renders the phishing scan screen and starts a scan", async () => {
  getIncidents.mockResolvedValue({ data: [] });
  scanInbox.mockResolvedValue({ data: { incidents: [] } });

  render(<App />);

  expect(
    screen.getByRole("heading", { name: /phishing detection/i })
  ).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: /scan gmail inbox/i }));

  await waitFor(() => {
    expect(scanInbox).toHaveBeenCalledTimes(1);
    expect(
      screen.getByRole("button", { name: /scan gmail inbox/i })
    ).toBeEnabled();
  });
});

test("shows an error when an inbox scan fails", async () => {
  getIncidents.mockResolvedValue({ data: [] });
  scanInbox.mockRejectedValue({
    response: { status: 502, data: { detail: "Gmail API request failed (HTTP 403)" } },
  });

  render(<App />);
  fireEvent.click(screen.getByRole("button", { name: /scan gmail inbox/i }));

  expect(await screen.findByRole("alert")).toHaveTextContent(
    "Scan failed: Gmail API request failed (HTTP 403)"
  );
  expect(
    screen.getByRole("button", { name: /scan gmail inbox/i })
  ).toBeEnabled();
});
