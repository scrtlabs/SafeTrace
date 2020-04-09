const FlashMessage = ({ location }) => {
  const message = location && location.state ? location.state : null;

  return message;
};

export default FlashMessage;
