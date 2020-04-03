import React from "react";
import DayPickerInput from "react-day-picker/DayPickerInput";

import "./style.css";
import styled from "styled-components";
import colors from "Theme/colors";
import dateFnsFormat from "date-fns/format";
import dateFnsParse from "date-fns/parse";
import { DateUtils } from "react-day-picker";

const DATE_FORMAT = "L/d/yyyy";
const formatDate = (date, format, locale) =>
  dateFnsFormat(date, format, { locale });

const parseDate = (str, format, locale) => {
  const parsed = dateFnsParse(str, format, new Date(), { locale });
  if (DateUtils.isDate(parsed)) {
    return parsed;
  }
  return undefined;
};

const DatePicker = ({ className, ...props }) => (
  <DayPickerInput
    {...props}
    classNames={{ container: className, overlay: "" }}
    format={DATE_FORMAT}
    parseDate={parseDate}
    formatDate={formatDate}
    placeholder="MM/DD/YYYY"
    dayPickerProps={{
      fromMonth: new Date(2019, 11, 1),
      toMonth: new Date(),
      disabledDays: {
        before: new Date(2019, 11, 1),
        after: new Date()
      }
    }}
  />
);

const StyledDayPicker = styled(DatePicker)`
  height: 60px;
  position: relative;

  & > input {
    border: 1px solid ${colors.grey.light};
    height: 60px;
    width: 100%;
    padding: 10px;
    border-radius: 6px;
    background: white;
    cursor: pointer;
    transition .5s;
    &:active,
    &:focus {
      outline: none;
      border-color: ${colors.primary.main}
    }
  }
`;

export default StyledDayPicker;
