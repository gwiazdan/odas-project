import { Bounce } from "react-toastify";
import type { ToastContainerProps } from "react-toastify";

export const toastConfig: ToastContainerProps = {
  position: "bottom-right",
  autoClose: 5000,
  hideProgressBar: false,
  newestOnTop: true,
  closeOnClick: false,
  rtl: false,
  pauseOnFocusLoss: true,
  draggable: true,
  pauseOnHover: true,
  theme: "dark" as const,
  transition: Bounce,
};
